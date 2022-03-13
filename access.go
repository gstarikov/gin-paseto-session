package gin_paseto_session

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func (m Middleware) Access(c *gin.Context) {
	_, _, payload, err := m.extractContextToken(AccessTokenCookiesName, c)
	if err != nil {
		m.cfg.ErrorLogger(c, err)
	}
	switch {
	case errors.Is(err, ErrTokenAbscent),
		errors.Is(err, ErrTokenExpired): // браузер не пришлёт просроченный токен
		if !m.cfg.DisableAutoRefresh {
			// do automatic refresh
			switch err, _, newPayload := m.refresh(c); {
			case err != nil:
				m.cfg.ErrorLogger(c, err)
				c.Status(http.StatusUnauthorized)
				c.Abort()
				return
			default: // no error, new cookies are set & etc
				m.cfg.ErrorLogger(c, ErrDoAutoRefresh)
				payload = newPayload
			}
			break
		}
		fallthrough
	case errors.Is(err, ErrTokenInvalid):
		if m.cfg.RefreshURL != "" {
			c.Redirect(http.StatusTemporaryRedirect, m.cfg.RefreshURL) // редирект с сохранением метода
		} else {
			c.Status(http.StatusUnauthorized)
		}
		c.Abort()

		return
	case err != nil:
		c.Status(http.StatusUnauthorized)
		c.Abort()

		return
	}

	if m.cfg.RBAC != nil {
		if err = m.cfg.RBAC(c, payload); err != nil {
			m.cfg.ErrorLogger(c, err)
			c.Status(http.StatusUnauthorized)
			c.Abort()

			return
		}
	}

	c.Set(PayloadKey, payload)

	c.Next()
}
