package jwt

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

const privateKeyPath = "fixtures/private-key.pem"

func TestJWT_Auth_Header(t *testing.T) {
	token, err := generateValidToken()
	assert.NoError(t, err)

	testCases := []struct {
		name       string
		header     string
		statusCode int
	}{
		{"valid auth scheme valid token", fmt.Sprintf("Bearer %s", token), http.StatusOK},
		{"valid auth scheme valid token case insensitive", fmt.Sprintf("bEaReR %s", token), http.StatusOK},
		{"valid auth scheme invalid token", "Bearer invalid", http.StatusUnauthorized},
		{"invalid auth scheme valid token", fmt.Sprintf("NotBearer %s", token), http.StatusUnauthorized},
		{"invalid auth scheme invalid token", "NotBearer invalid", http.StatusUnauthorized},
		{"invalid header format", "Bearer", http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key, err := loadPrivateKey(privateKeyPath)
			assert.NoError(t, err)

			e.Use(JWT(key))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, tc.header)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWT_Auth_Cookie(t *testing.T) {
	token, err := generateValidToken()
	assert.NoError(t, err)

	validCookie := &http.Cookie{
		Name:  "access_token",
		Value: string(token),
		Path:  "/",
	}

	wrongNameCookie := &http.Cookie{
		Name:  "not_access_token",
		Value: string(token),
		Path:  "/",
	}

	invalidTokenCookie := &http.Cookie{
		Name:  "access_token",
		Value: "invalid",
		Path:  "/",
	}

	testCases := []struct {
		name       string
		cookie     *http.Cookie
		statusCode int
	}{
		{"valid cookie", validCookie, http.StatusOK},
		{"wrong cookie name", wrongNameCookie, http.StatusUnauthorized},
		{"invalid token cookie", invalidTokenCookie, http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key, err := loadPrivateKey(privateKeyPath)
			assert.NoError(t, err)

			e.Use(JWT(key))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(tc.cookie)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWT_ReturnStatus(t *testing.T) {
	token, err := generateValidToken()
	assert.NoError(t, err)

	expToken, err := generateExpiredToken()
	assert.NoError(t, err)

	nbfToken, err := generateFutureNotBefore()
	assert.NoError(t, err)

	iatToken, err := generateInvalidIssuedAt()
	assert.NoError(t, err)

	testCases := []struct {
		name       string
		token      []byte
		statusCode int
	}{
		{"valid", token, http.StatusOK},
		{"expired", expToken, http.StatusUnauthorized},
		{"not before in future", nbfToken, http.StatusUnauthorized},
		{"invalid issued at", iatToken, http.StatusUnauthorized},
		{"invalid", []byte("invalid"), http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key, err := loadPrivateKey(privateKeyPath)
			assert.NoError(t, err)

			e.Use(JWT(key))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", tc.token))
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWTWithConfig_Key_Panic(t *testing.T) {
	e := echo.New()

	assert.Panics(t, func() { e.Use(JWTWithConfig(Config{})) })
}

func TestJWTWithConfig_Skipper(t *testing.T) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	e.Use(JWTWithConfig(Config{
		Key:     "key",
		Skipper: func(c echo.Context) bool { return true },
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestJWTWithConfig_RefreshToken_Defaults(t *testing.T) {
	e := echo.New()

	e.POST("/auth/refresh", func(c echo.Context) error {
		return c.String(http.StatusOK, c.Get(DefaultConfig.RefreshToken.ContextKeyEncoded).(string))
	})

	key, err := loadPrivateKey(privateKeyPath)
	assert.NoError(t, err)

	e.Use(JWTWithConfig(Config{
		Key:             key,
		UseRefreshToken: true,
		RefreshToken:    &RefreshToken{},
	}))

	token, err := generateValidToken()
	assert.NoError(t, err)

	b := fmt.Sprintf(`{"refresh_token": "%s"}`, token)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer([]byte(b)))
	req.Header.Add("Content-Type", echo.MIMEApplicationJSON)
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, string(token), resp.Body.String())
}

func TestJWTWithConfig_RefreshToken_Malformed(t *testing.T) {
	token, err := generateValidToken()
	assert.NoError(t, err)

	testCases := []struct {
		name        string
		contentType string
		body        *bytes.Buffer
		statusCode  int
		msg         string
	}{
		{
			"wrong content type",
			"wrong",
			bytes.NewBuffer([]byte(fmt.Sprintf(`{"refresh_token": "%s"}`, token))),
			http.StatusBadRequest,
			"Request malformed",
		},
		{
			"no body",
			echo.MIMEApplicationJSON,
			&bytes.Buffer{},
			http.StatusBadRequest,
			"Request malformed",
		},
		{
			"malformed json body",
			echo.MIMEApplicationJSON,
			bytes.NewBuffer([]byte("{]")),
			http.StatusBadRequest,
			"Request malformed",
		},
		{
			"missing body key",
			echo.MIMEApplicationJSON,
			bytes.NewBuffer([]byte(fmt.Sprintf(`{"wrong": "%s"}`, token))),
			http.StatusUnprocessableEntity,
			"Body missing 'refresh_token' key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.POST("/auth/refresh", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key, err := loadPrivateKey(privateKeyPath)
			assert.NoError(t, err)

			e.Use(JWTWithConfig(Config{
				Key:             key,
				UseRefreshToken: true,
				RefreshToken:    &RefreshToken{},
			}))

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", tc.body)
			req.Header.Add("Content-Type", tc.contentType)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
			assert.Contains(t, resp.Body.String(), tc.msg)
		})
	}
}

func TestJWTWithConfig_AfterParseFunc(t *testing.T) {
	fn := func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError { return nil }
	errFn := func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError {
		return &echo.HTTPError{Code: http.StatusTeapot}
	}

	testCases := []struct {
		name       string
		fn         func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError
		statusCode int
	}{
		{"no error", fn, http.StatusOK},
		{"error", errFn, http.StatusTeapot},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key, err := loadPrivateKey(privateKeyPath)
			assert.NoError(t, err)

			e.Use(JWTWithConfig(Config{
				Key:            key,
				AfterParseFunc: tc.fn,
			}))

			token, err := generateValidToken()
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func afterParseHeader(_ echo.Context, _ jwt.Token, _ string, src TokenSource) *echo.HTTPError {
	if src.String() == Header.String() {
		return nil
	}

	return &echo.HTTPError{Code: http.StatusInternalServerError}
}

func afterParseCookie(_ echo.Context, _ jwt.Token, _ string, src TokenSource) *echo.HTTPError {
	if src == Cookie {
		return nil
	}

	return &echo.HTTPError{Code: http.StatusInternalServerError}
}

func TestJWTWithConfig_AfterParseFunc_Source(t *testing.T) {
	testCases := []struct {
		name   string
		source TokenSource
		fn     func(echo.Context, jwt.Token, string, TokenSource) *echo.HTTPError
	}{
		{"header source", Header, afterParseHeader},
		{"cookie source", Cookie, afterParseCookie},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key, err := loadPrivateKey(privateKeyPath)
			assert.NoError(t, err)

			e.Use(JWTWithConfig(Config{
				Key:            key,
				AfterParseFunc: tc.fn,
			}))

			token, err := generateValidToken()
			assert.NoError(t, err)

			cookie := &http.Cookie{
				Name:  "access_token",
				Value: string(token),
				Path:  "/",
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.source == Header {
				req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
			} else {
				req.AddCookie(cookie)
			}
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestJWTWithConfig_ExemptMethods(t *testing.T) {
	testCases := []struct {
		name       string
		methods    []string
		statusCode int
	}{
		{"get 200", []string{http.MethodGet}, http.StatusOK},
		{"post 200", []string{http.MethodPost}, http.StatusOK},
		{"put 200", []string{http.MethodPut}, http.StatusOK},
		{"patch 200", []string{http.MethodPatch}, http.StatusOK},
		{"delete 200", []string{http.MethodDelete}, http.StatusOK},
		{"options 200", []string{http.MethodOptions}, http.StatusOK},
		{"get 401", []string{http.MethodPost}, http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.Any("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			e.Use(JWTWithConfig(Config{
				ExemptMethods: tc.methods,
				Key:           "key",
			}))

			req := httptest.NewRequest(tc.methods[0], "/", nil)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestJWTWithConfig_ExemptRoutes(t *testing.T) {
	testCases := []struct {
		name       string
		pattern    string
		route      string
		statusCode int
	}{
		{"root", "/", "/", http.StatusOK},
		{"users", "/users", "/users", http.StatusOK},
		{"users_id", "/users/:id", "/users/1", http.StatusOK},
		{"users_books", "/users/:id/books", "/users/1/books", http.StatusOK},
		{"users_books_id", "/users/:id/books/:id", "/users/1/books/1", http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET(tc.route, func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			e.Use(JWTWithConfig(Config{
				ExemptRoutes: map[string][]string{
					tc.route: {http.MethodGet},
				},
				Key: "key",
			}))

			req := httptest.NewRequest(http.MethodGet, tc.route, nil)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestJWTWithConfig_OptionalRoutes(t *testing.T) {
	testCases := []struct {
		name       string
		routes     map[string][]string
		statusCode int
	}{
		{"success", map[string][]string{"/": {http.MethodGet}}, http.StatusOK},
		{"fail", map[string][]string{"/": {http.MethodPost}}, http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key, err := loadPrivateKey(privateKeyPath)
			assert.NoError(t, err)

			e.Use(JWTWithConfig(Config{
				OptionalRoutes: tc.routes,
				Key:            key,
			}))

			token, err := generateExpiredToken()
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWT_Route_Not_Found(t *testing.T) {
	testCases := []struct {
		name       string
		endpoint   string
		method     string
		statusCode int
	}{
		{"wrong path", "/wrong", http.MethodGet, http.StatusNotFound},
		{"wrong method", "/", http.MethodPost, http.StatusMethodNotAllowed},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			key, err := loadPrivateKey(privateKeyPath)
			assert.NoError(t, err)

			e.Use(JWT(key))

			req := httptest.NewRequest(tc.method, tc.endpoint, nil)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func generateValidToken() ([]byte, error) {
	t := time.Now()
	return generateToken(t, t, t.Add(time.Minute*10))
}

func generateExpiredToken() ([]byte, error) {
	t := time.Now().Add(-time.Minute * 10)
	return generateToken(t, t, t)
}

func generateFutureNotBefore() ([]byte, error) {
	t := time.Now()
	return generateToken(t, t.Add(time.Minute*10), t.Add(time.Minute*9))
}

func generateInvalidIssuedAt() ([]byte, error) {
	t := time.Now()
	return generateToken(t.Add(time.Minute*10), t, t)
}

func generateToken(iat time.Time, nbf time.Time, exp time.Time) ([]byte, error) {
	key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}

	builder := jwt.NewBuilder().
		Subject("123").
		Issuer("test").
		IssuedAt(iat).
		NotBefore(nbf).
		Expiration(exp)

	token, err := builder.Build()
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block: %v", err)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}
