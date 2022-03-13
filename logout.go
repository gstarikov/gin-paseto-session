package gin_paseto_session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
)

func (m Middleware) Logout(c *gin.Context) {
	if err := m.logout(c); err != nil && m.cfg.ErrorLogger != nil {
		m.cfg.ErrorLogger(c, err)
		c.Status(http.StatusBadRequest)
	}
}

func (m Middleware) logout(c *gin.Context) (err error) {
	// сбрасываем куки
	cookies := []string{
		RefreshTokenCookiesName,
		AccessTokenCookiesName,
	}
	for _, v := range cookies {
		c.SetCookie(v, "", 0, "/", "", false, false)
	}

	// извлекаем и проверяем на актуальность
	var encodedToken string
	var payload interface{}
	_, encodedToken, payload, err = m.extractContextToken(RefreshTokenCookiesName, c)
	if err != nil {
		return
	}

	// удаляем из БД рефреш токен
	return m.cfg.RemoveRefreshAtStorage(c, encodedToken, payload)
}

func (m Middleware) extractContextToken(cookieName string, c *gin.Context) (interface{}, string, interface{}, error) {
	var rt interface{}
	var token string
	var payload interface{}
	var err error
	// извлекаем из куки
	token, err = c.Cookie(cookieName)

	switch {
	case errors.Is(err, http.ErrNoCookie) || token == "":
		return rt, token, payload, ErrTokenAbscent
	case err != nil:
		return rt, token, payload, fmt.Errorf("unexpected error: %w", err)
	}

	// верифицируем
	var jsonToken []byte
	if err = m.pv2.Verify(token, m.cfg.PublicKey, &jsonToken, nil); err != nil {
		return rt, token, payload, ErrTokenInvalid
	}

	// угадываем тип
	var bt *baseToken
	switch cookieName {
	case RefreshTokenCookiesName:
		v := &RefreshToken{}
		rt = v
		bt = &v.baseToken
	case AccessTokenCookiesName:
		v := &AccessToken{}
		rt = v
		bt = &v.baseToken
	default:
		panic("unknown type")
	}

	if err = json.Unmarshal(jsonToken, rt); err != nil {
		return rt, token, payload, ErrTokenInvalid
	}

	// валидируем
	if err = m.verifyToken(*bt); err != nil {
		return rt, token, payload, err
	}

	// извлкаем payload
	ptrPayload := reflect.New(m.cfg.PayloadType).Interface() // что бы извлечение норм отработало
	if err = json.Unmarshal(bt.Payload, ptrPayload); err != nil {
		return rt, token, payload, ErrTokenInvalid
	}
	payload = reflect.Indirect(reflect.ValueOf(ptrPayload)).Interface()

	return rt, token, payload, nil
}

func (m Middleware) verifyToken(br baseToken) error {
	nowUT := time.Now().Unix()
	switch {
	case br.IssuedAt > nowUT:

		return ErrTokenInvalid
	case br.Expiration <= nowUT:

		return ErrTokenExpired
	}

	return nil
}
