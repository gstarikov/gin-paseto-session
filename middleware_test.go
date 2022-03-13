package gin_paseto_session

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestMiddleware_Login(t *testing.T) {

	type testPayloadType struct {
		Field string
	}

	const Location = "Location"

	// инициализируем мидлваре
	b, _ := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	privateKey := ed25519.PrivateKey(b)

	b, _ = hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	publicKey := ed25519.PublicKey(b)

	expirationRefresh := time.Second * 3
	expirationAccess := time.Second * 1

	var storedToken string
	var storedPayload testPayloadType
	var detectedErr error

	var removedToken string
	var removedPayload testPayloadType

	var replaceOldToken, replaceNewToken string
	var replacePayload testPayloadType

	var rbacErr error
	var rbacCBPayload, rbacPayload testPayloadType
	var rbacAccCalled, rbacPayloadExist bool

	cfg := Config{
		RefreshURL:        "/refresh",
		PrivateKey:        privateKey,
		PublicKey:         publicKey,
		ExpirationRefresh: expirationRefresh,
		ExpirationAccess:  expirationAccess,
		ErrorLogger: func(c *gin.Context, err error) {
			detectedErr = err
		},
		StoreRefreshAtStorage: func(c *gin.Context, token string, footprint interface{}) error {
			storedToken = token
			storedPayload = footprint.(testPayloadType) // это ж тест, если что, пусть падает по панике
			return nil
		},
		RemoveRefreshAtStorage: func(c *gin.Context, token string, payload interface{}) error {
			removedToken = token
			removedPayload = payload.(testPayloadType)
			return nil
		},
		PayloadType: reflect.TypeOf(testPayloadType{}),
		LoginURL:    "/login",
		ReplaceRefreshAtStorage: func(c *gin.Context, oldToken, newToken string, payload interface{}) error {
			replaceOldToken = oldToken
			replaceNewToken = newToken
			replacePayload = payload.(testPayloadType)
			return nil
		},
		RBAC: func(c *gin.Context, payload interface{}) error {
			rbacCBPayload = payload.(testPayloadType)
			return rbacErr
		},
		ReturnToRef:        true,
		DisableAutoRefresh: true,
	}

	mw, err := New(cfg)

	require.NoError(t, err)
	require.NotNil(t, mw)

	testPayload := testPayloadType{
		Field: "testPayload",
	}

	type testCase struct {
		Method     string
		Target     string
		Handler    func(c *gin.Context)
		Status     int
		Assert     func(w *httptest.ResponseRecorder)
		Prepare    func(req *http.Request)
		PrepareEng func(r *gin.Engine)
		Cookies    []*http.Cookie
	}
	var i int
	var test testCase

	var tests []testCase
	setCookiesStepOne := func(req *http.Request) {
		for _, v := range tests[0].Cookies {
			req.AddCookie(v)
		}
	}

	tests = []testCase{
		{ // 0 тестируем создание сесиии
			Method: http.MethodPost,
			Target: "/",
			Handler: func(c *gin.Context) {
				require.NoError(t, mw.NewSession(c, testPayload))
			},
			Status: http.StatusOK,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.Equal(t, testPayload, storedPayload)
				assert.NotEmpty(t, storedToken)
				cookies := w.Result().Cookies()
				assert.Equalf(t, "refresh_token", cookies[0].Name, "case(%d)", i)
				assert.Equalf(t, "access_token", cookies[1].Name, "case(%d)", i)
				for i := range cookies {
					assert.NotEmptyf(t, cookies[i].Value, "case(%d)", i)
				}
			},
		},
		{ // 1 тестируем logout без куки
			Method:  http.MethodGet,
			Target:  "/",
			Handler: mw.Logout,
			Status:  http.StatusBadRequest,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.Equalf(t, ErrTokenAbscent, detectedErr, "case(%d)", i)
				assert.Emptyf(t, removedToken, "case(%d)", i)
				assert.Emptyf(t, removedPayload, "case(%d)", i)
			},
		},
		{ // 2 логаут
			Method:  http.MethodGet,
			Target:  "/",
			Handler: mw.Logout,
			Status:  http.StatusOK,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.Equalf(t, nil, detectedErr, "case(%d)", i)
				assert.Equalf(t, storedToken, removedToken, "case(%d)", i)
				assert.Equalf(t, storedPayload, removedPayload, "case(%d)", i)
			},
			Prepare: setCookiesStepOne,
		},
		{ // 3 тест рефреша без кук
			Method:  http.MethodGet,
			Target:  "/",
			Handler: mw.Refresh,
			Status:  http.StatusSeeOther,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.Equalf(t, cfg.LoginURL, w.Header().Get("location"), "case(%d)", i)
				assert.Equalf(t, ErrTokenAbscent, detectedErr, "case(%d)", i)
			},
		},
		{ // 4 тест рефреша
			Method:  http.MethodGet,
			Target:  "/",
			Handler: mw.Refresh,
			Status:  http.StatusOK,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.Equalf(t, w.Code, http.StatusOK, "case(%d)", i)
				assert.Equalf(t, nil, detectedErr, "case(%d)", i)

				assert.Equalf(t, storedToken, removedToken, "case(%d)", i)
				assert.Equalf(t, storedPayload, removedPayload, "case(%d)", i)

				assert.Equalf(t, storedToken, replaceOldToken, "case(%d)", i)
				assert.Equalf(t, storedPayload, replacePayload, "case(%d)", i)
				assert.NotEmptyf(t, replaceNewToken, "case(%d)", i)
				assert.NotEqualf(t, storedToken, replaceNewToken, "case(%d)", i)

				for i, v := range tests[0].Cookies {
					old := w.Result().Cookies()[i]
					assert.Equalf(t, old.Name, v.Name, "case(%d)", i) // криво, но порядок не должен меняться просто так
					if i == 0 {
						assert.NotEqualf(t, old.Value, v.Value, "case(%d)", i) // +1 только у refresh токена, у access скорее всего 1 секунда не успеет пройти
					}
				}
			},
			Prepare: setCookiesStepOne,
		},
		{ // 5 тест редиректа в рефреше (возврат обратно)
			Method:  http.MethodGet,
			Target:  "/",
			Handler: mw.Refresh,
			Status:  http.StatusTemporaryRedirect,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.Equalf(t, nil, detectedErr, "case(%d)", i)

				assert.Equalf(t, storedToken, removedToken, "case(%d)", i)
				assert.Equalf(t, storedPayload, removedPayload, "case(%d)", i)

				assert.Equalf(t, storedToken, replaceOldToken, "case(%d)", i)
				assert.Equalf(t, storedPayload, replacePayload, "case(%d)", i)
				assert.NotEmptyf(t, replaceNewToken, "case(%d)", i)
				assert.NotEqualf(t, storedToken, replaceNewToken, "case(%d)", i)

				for i, v := range tests[0].Cookies {
					old := w.Result().Cookies()[i]
					assert.Equalf(t, old.Name, v.Name, "case(%d)", i) // криво, но порядок не должен меняться просто так
					if i == 0 {
						assert.NotEqualf(t, old.Value, v.Value, "case(%d)", i) // +1 только у refresh токена, у access скорее всего 1 секунда не успеет пройти
					}
				}

				assert.Equalf(t, "https://protectedEndpoint.io/first", w.Header().Get(Location), "case(%d)", i)
			},
			Prepare: func(req *http.Request) {
				setCookiesStepOne(req)
				req.Header.Set("referer", "https://protectedEndpoint.io/first")
			},
		},
		{ // 6 тест access. без куки
			Method: http.MethodGet,
			Target: "/",
			Handler: func(c *gin.Context) {
				rbacAccCalled = true
				var iFace interface{}
				iFace, rbacPayloadExist = c.Get(PayloadKey)
				if rbacPayloadExist {
					rbacCBPayload = iFace.(testPayloadType)
				}
			},
			Status: http.StatusTemporaryRedirect,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.Equalf(t, cfg.RefreshURL, w.Header().Get("location"), "case(%d)", i)
				assert.Equalf(t, ErrTokenAbscent, detectedErr, "case(%d)", i)
				assert.Falsef(t, rbacAccCalled, "case(%d)", i)
				assert.Falsef(t, rbacPayloadExist, "case(%d)", i)
				assert.Emptyf(t, rbacCBPayload, "case(%d)", i)
				assert.Emptyf(t, rbacPayload, "case(%d)", i)
			},
			PrepareEng: func(r *gin.Engine) {
				r.Use(mw.Access)
			},
		},
		{ // 7 тест access, с куками
			Method: http.MethodGet,
			Target: "/",
			Handler: func(c *gin.Context) {
				rbacAccCalled = true
				var iFace interface{}
				iFace, rbacPayloadExist = c.Get(PayloadKey)
				if rbacPayloadExist {
					rbacPayload = iFace.(testPayloadType)
				}
			},
			Status: http.StatusOK,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.NoErrorf(t, detectedErr, "case(%d)", i)
				assert.Truef(t, rbacAccCalled, "case(%d)", i)
				assert.Truef(t, rbacPayloadExist, "case(%d)", i)
				assert.Equalf(t, storedPayload, rbacCBPayload, "case(%d)", i)
				assert.Equalf(t, storedPayload, rbacPayload, "case(%d)", i)
			},
			PrepareEng: func(r *gin.Engine) {
				r.Use(mw.Access)
			},
			Prepare: func(req *http.Request) {
				setCookiesStepOne(req)
			},
		},
		{ // 8 тест автоматического рефреша. успешный
			Method: http.MethodGet,
			Target: "/",
			Handler: func(c *gin.Context) {
				// вызов долеж автоматом пройти
				rbacAccCalled = true
			},
			Status: http.StatusOK,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.Equalf(t, ErrDoAutoRefresh, detectedErr, "case(%d)", i) //  да, логируется ошибка отсутствия токена т.к. браузер не отправляет токен
				assert.Truef(t, rbacAccCalled, "case(%d)", i)                  // но вызов всё равно выполняется т.к. авторефреш
			},
			PrepareEng: func(r *gin.Engine) {
				mw.cfg.DisableAutoRefresh = false
				r.Use(mw.Access)
			},
			Prepare: func(req *http.Request) {
				var ref *http.Cookie
				for _, cookie := range tests[0].Cookies {
					switch {
					case cookie.Name == RefreshTokenCookiesName:
						ref = cookie
					}
				}
				req.AddCookie(ref)
				rbacAccCalled = false
			},
		},
		{ // 9 тест работы по новому access tokens
			Method: http.MethodGet,
			Target: "/",
			Handler: func(c *gin.Context) {
				// вызов долеж автоматом пройти
				rbacAccCalled = true
			},
			Status: http.StatusOK,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.NoErrorf(t, detectedErr, "case(%d)", i)
				assert.Truef(t, rbacAccCalled, "case(%d)", i)
			},
			PrepareEng: func(r *gin.Engine) {
				mw.cfg.DisableAutoRefresh = false
				r.Use(mw.Access)
			},
			Prepare: func(req *http.Request) {
				for _, cookie := range tests[8].Cookies {
					req.AddCookie(cookie)
				}
				rbacAccCalled = false
			},
		},
		{ // 10 тест автоматического рефреша. неуспешный т.к. просрочен refresh токен
			Method: http.MethodGet,
			Target: "/",
			Handler: func(c *gin.Context) {
				// не должен пройти вызов
				rbacAccCalled = true
			},
			Status: http.StatusUnauthorized,
			Assert: func(w *httptest.ResponseRecorder) {
				assert.Equalf(t, ErrTokenAbscent, detectedErr, "case(%d)", i) // token просрочен
				assert.Falsef(t, rbacAccCalled, "case(%d)", i)                // вызов не выполнен
			},
			PrepareEng: func(r *gin.Engine) {
				mw.cfg.DisableAutoRefresh = false
				r.Use(mw.Access)
			},
			Prepare: func(req *http.Request) {
				// не ставим токены
				rbacAccCalled = false
			},
		},
	}

	for i, test = range tests {
		detectedErr = nil
		w := httptest.NewRecorder()
		_, r := gin.CreateTestContext(w)
		if test.PrepareEng != nil {
			test.PrepareEng(r)
		}
		r.Handle(test.Method, test.Target, test.Handler)
		req := httptest.NewRequest(test.Method, test.Target, nil)
		if test.Prepare != nil {
			test.Prepare(req)
		}
		r.ServeHTTP(w, req)
		assert.Equalf(t, test.Status, w.Code, "case(%d)", i)
		tests[i].Cookies = w.Result().Cookies()
		if test.Assert != nil {
			test.Assert(w)
		}
	}
}
