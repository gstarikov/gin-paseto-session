package gin_paseto_session

import (
	"encoding/json"
	"time"
)

type baseToken struct {
	Expiration int64
	IssuedAt   int64
	Payload    json.RawMessage
}

type RefreshToken struct {
	baseToken
	Generation uint64
}

type AccessToken struct {
	baseToken
}

func (m Middleware) updateToken(token interface{}, nw time.Time) (updated interface{}, maxage time.Duration) {
	var basePtr *baseToken
	switch t := token.(type) {
	case *RefreshToken:
		rt := &RefreshToken{}
		*rt = *t
		rt.Generation++
		basePtr = &rt.baseToken
		updated = rt
		maxage = m.cfg.ExpirationRefresh
	case *AccessToken:
		at := &AccessToken{}
		*at = *t
		basePtr = &at.baseToken
		updated = at
		maxage = m.cfg.ExpirationAccess
	default:
		panic("wrong type")
	}

	basePtr.IssuedAt = nw.Unix()
	basePtr.Expiration = nw.Add(maxage).Unix()

	return
}
