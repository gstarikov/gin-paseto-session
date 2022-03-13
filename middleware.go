package gin_paseto_session

import (
	"crypto/ed25519"
	"errors"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/o1egl/paseto"
)

type (
	Middleware struct {
		cfg Config
		pv2 *paseto.V2
	}

	Config struct {
		RefreshURL         string
		LoginURL           string
		ReturnToRef        bool // will refresh produce 307 redirect in case of noon empty referer
		DisableAutoRefresh bool // will automatically refresh access token in case of expire or do 401 or redirect

		PrivateKey ed25519.PrivateKey // is necessary only for NewSession & Refresh to generate new access & refresh tockens
		PublicKey  ed25519.PublicKey

		ExpirationAccess  time.Duration
		ExpirationRefresh time.Duration

		ErrorLogger             ErrorLogger
		StoreRefreshAtStorage   StoreRefreshAtStorage
		RemoveRefreshAtStorage  RemoveRefreshAtStorage
		ReplaceRefreshAtStorage ReplaceRefreshAtStorage
		PayloadType             reflect.Type // necessary to convert from token to struct
		RBAC                    RBAC
	}

	ErrorLogger             func(c *gin.Context, err error)
	StoreRefreshAtStorage   func(c *gin.Context, token string, payload interface{}) error
	RemoveRefreshAtStorage  func(c *gin.Context, token string, payload interface{}) error
	ReplaceRefreshAtStorage func(c *gin.Context, oldToken, newToken string, payload interface{}) error
	RBAC                    func(c *gin.Context, payload interface{}) error
)

var (
	ErrTokenAbscent            = errors.New("token abscent")
	ErrTokenExpired            = errors.New("token expired")
	ErrTokenInvalid            = errors.New("token invalid")
	ErrPayloadMismatch         = errors.New("payload mismatch")
	ErrNeedPayloadType         = errors.New("need payload type to construct it on decode time")
	ErrNeedRefreshTokenStorage = errors.New("must have persistent refresh token storage. without it security level will be to low")
	ErrNeedRBAC                = errors.New("must have RBAC checker function")
	ErrDoAutoRefresh           = errors.New("successfully do autorefresh access token") // there is no success logging, so do error
)

const PayloadKey = "payload"

func New(cfg Config) (*Middleware, error) {
	switch {
	case cfg.PayloadType == nil:
		return nil, ErrNeedPayloadType
	case cfg.ReplaceRefreshAtStorage == nil:
		return nil, ErrNeedRefreshTokenStorage
	case cfg.RBAC == nil:
		return nil, ErrNeedRBAC
	}

	return &Middleware{
		cfg: cfg,
		pv2: paseto.NewV2(),
	}, nil
}
