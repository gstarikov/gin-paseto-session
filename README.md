# gin-paseto-session
golang gin middleware &amp; auth library to paseto tokens

This library implements session support on paseto token base. Works on gin web server.
Methods
- session.Login - create new session:
  - structs - payload и footprint, serialize to json and embed into access & refresh tokens
  - in the gin.Context writes  access & refresh tokens
  - write refresh token to DB via callback (library user provides callback handler)
  - if you want leave only one session, do LogoutAll before Login
- session.Logout - gin.Handler, invalidates refresh token via callback call
- session.LogoutAll - gin.Handler, invalidates all refresh tokens (via callback calls)
- session.Refresh - gin.Handler, do refresh of the reftesh token
  - in case of invalid refresh token will return http 401 code
- session.Access - gin middleware,
  - extract from request access token, check for validity and, in case of invalid do redirect to refresh (configurable, may do autorefresh & etc)
  - extract from token payload & footprint and calls callback to check RBAC (i dont use it in real cases, but it may be helpful for you)
  - extracted payload writes to gin.Context

links:
- https://paragonie.com/files/talks/NoWayJoseCPV2018.pdf

use sample

    type SessionData struct{
        User string
    }

 	cfg := Config{
 		RefreshURL:        "/auth/refresh",
 		PrivateKey:        privateKey,
 		PublicKey:         publicKey,
 		ExpirationRefresh: expirationRefresh,
 		ExpirationAccess:  expirationAccess,
 		ErrorLogger: func(c *gin.Context, err error) {},
 		StoreRefreshAtStorage: func(token string, footprint interface{}) error {},
 		RemoveRefreshAtStorage: func(token string, payload interface{}) error {},
 		PayloadType: reflect.TypeOf(SessionData{}),
 		LoginURL:    "/auth/login",
 		ReplaceRefreshAtStorage: func(oldToken, newToken string, payload interface{}) error {
 			return nil
 		},
 		RBAC: func(c *gin.Context, payload interface{}) error {
 			return nil
 		},
 	}

    eng := gin.New()
    mw, err := New(cfg)
    authGroup := eng.Group("/auth")
 	protGroup := eng.Group("/")
 	protGroup.Use(mw.Access)

 	authGroup.GET("/refresh", mw.Refresh)
 	authGroup.GET("/logout", mw.Logout)
    authGroup.POST("/login", func(c *gin.Context) {
        mw.NewSession(c, testPayload)
    })

    protGroup.GET("/", func(c *gin.Context) {
        iFace, rbacPayloadExist := c.Get(PayloadKey)
        if rbacPayloadExist {
            rbacPayload = iFace.(testPayloadType)
        }
    })
