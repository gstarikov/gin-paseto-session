package gin_paseto_session

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func (m Middleware) Refresh(c *gin.Context) {
	err, newTokenAccess, _ := m.refresh(c)
	if err != nil {
		m.cfg.ErrorLogger(c, err)
	}
	switch {
	case errors.Is(err, ErrTokenExpired),
		errors.Is(err, ErrTokenAbscent):
		if m.cfg.LoginURL != "" {
			c.Redirect(http.StatusSeeOther, m.cfg.LoginURL)
		} else {
			c.Status(http.StatusUnauthorized)
		}
	case err != nil:
		c.Status(http.StatusBadRequest)
	default:
		if m.cfg.ReturnToRef {
			from := c.Request.Referer()
			if from != "" {
				c.Redirect(http.StatusTemporaryRedirect, from)
			}
		}
		c.JSON(http.StatusOK, newTokenAccess)
	}
}

func (m Middleware) refresh(c *gin.Context) (err error, newTokenAccess, payload interface{}) {
	var oldToken interface{}
	var encodedToken string
	var newToken interface{}
	var maxage time.Duration
	var newEncoded string
	var newEncodedAccess string
	var maxageAccess time.Duration

	// извлекаем токен & проверяем токен
	oldToken, encodedToken, payload, err = m.extractContextToken(RefreshTokenCookiesName, c)
	if err != nil {
		return err, nil, nil
	}

	// создаём новый refresh
	// refresh ++ к поколению
	// у всех - апдейт времени создания и срока действия
	nw := time.Now()
	newToken, maxage = m.updateToken(oldToken, nw)
	newEncoded, err = m.generateToken(newToken)
	if err != nil {
		return err, nil, nil
	}

	// новый access
	// nolint: exhaustivestruct
	newTokenAccess, maxageAccess = m.updateToken(&AccessToken{baseToken{
		Payload: oldToken.(*RefreshToken).Payload,
	}}, nw)
	newEncodedAccess, err = m.generateToken(newTokenAccess)
	if err != nil {
		return err, nil, nil
	}

	// апдейтим старый токен в БД на новый (андейт = защита от гонки)
	if err = m.cfg.ReplaceRefreshAtStorage(c, encodedToken, newEncoded, payload); err != nil {
		return fmt.Errorf("ReplaceRefreshAtStorage error: %w", err), nil, nil
	}

	// записываем токен в ответ
	setTokenCookies(c, RefreshTokenCookiesName, newEncoded, maxage)
	setTokenCookies(c, AccessTokenCookiesName, newEncodedAccess, maxageAccess)

	return nil, newTokenAccess, payload
}
