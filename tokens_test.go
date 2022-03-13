package gin_paseto_session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMiddleware_UpdateToken(t *testing.T) {
	m := Middleware{
		cfg: Config{
			ExpirationAccess:  time.Second,
			ExpirationRefresh: time.Minute,
		},
	}

	rt := RefreshToken{
		baseToken: baseToken{
			Expiration: 0,
			IssuedAt:   0,
			Payload:    nil,
		},
		Generation: 1,
	}

	st := time.Unix(0, 0)
	st = st.Add(time.Hour)
	upd, dur := m.updateToken(&rt, st)
	updRt := upd.(*RefreshToken)

	assert.Equal(t, m.cfg.ExpirationRefresh, dur)
	assert.Equal(t, st.Unix(), updRt.IssuedAt)
	assert.Equal(t, rt.Generation+1, updRt.Generation)
}
