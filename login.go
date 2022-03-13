package gin_paseto_session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	AccessTokenCookiesName  = "access_token"
	RefreshTokenCookiesName = "refresh_token"
)

func (m Middleware) NewSession(c *gin.Context, payload interface{}) error {
	// подготовили значения токенов
	IssuedAt := time.Now()

	rawMessage, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("payload marshall error: %w", err)
	}

	tokens := []struct {
		token   interface{}
		encoded string
		expire  time.Duration
		cookie  string
	}{
		{
			token: RefreshToken{
				baseToken: baseToken{
					Expiration: IssuedAt.Add(m.cfg.ExpirationRefresh).Unix(),
					IssuedAt:   IssuedAt.Unix(),
					Payload:    rawMessage,
				},
				Generation: 1,
			},
			expire: m.cfg.ExpirationRefresh,
			cookie: RefreshTokenCookiesName,
		},
		{
			token: AccessToken{
				baseToken: baseToken{
					Expiration: IssuedAt.Add(m.cfg.ExpirationAccess).Unix(),
					IssuedAt:   IssuedAt.Unix(),
					Payload:    rawMessage,
				},
			},
			expire: m.cfg.ExpirationAccess,
			cookie: AccessTokenCookiesName,
		},
	}

	// генерируем подписанные токены
	for i := range tokens {
		tokens[i].encoded, err = m.generateToken(tokens[i].token)
		if err != nil {
			return err
		}
	}

	// записываем в БД refresh токен
	if m.cfg.StoreRefreshAtStorage != nil {
		if err = m.cfg.StoreRefreshAtStorage(c, tokens[0].encoded, payload); err != nil {
			return err
		}
	}

	// записываем в куки
	for _, v := range tokens {
		setTokenCookies(c, v.cookie, v.encoded, v.expire)
	}

	// формируем тело для фронта
	body := tokens[1].token
	c.JSON(http.StatusOK, body)

	return nil
}

func setTokenCookies(c *gin.Context, key string, cookie string, maxage time.Duration) {
	c.SetCookie(
		key,
		cookie,
		int(maxage.Seconds()),
		"/",
		c.Request.URL.Hostname(),
		false, true) // ToDo: dont forget set up secure = true
}

func (m Middleware) generateToken(token interface{}) (encoded string, err error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	if err = enc.Encode(token); err != nil {
		return
	}

	encoded, err = m.pv2.Sign(
		m.cfg.PrivateKey,
		buf.Bytes(),
		nil)

	return
}
