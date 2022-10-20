package jwt

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

type Config struct {
	// Skipper defines a function to skip middleware.
	Skipper        middleware.Skipper
	ExemptRoutes   map[string][]string
	ExemptMethods  []string
	OptionalRoutes map[string][]string

	DecodeTokenFunc func(string, []jwt.ParseOption) (jwt.Token, error)
	AfterDecodeFunc func(echo.Context, jwt.Token) *echo.HTTPError
	Options         []jwt.ParseOption
	Key             interface{}

	TokenContextKey string
	CookieKey       string
	AuthHeader      string
}

var DefaultConfig = Config{
	Skipper:         middleware.DefaultSkipper,
	ExemptRoutes:    map[string][]string{},
	ExemptMethods:   []string{http.MethodOptions},
	OptionalRoutes:  map[string][]string{},
	DecodeTokenFunc: decodeToken,
	Options:         []jwt.ParseOption{},
	TokenContextKey: "token",
	CookieKey:       "access_token",
	AuthHeader:      "Authorization",
}

func JWT(key interface{}) echo.MiddlewareFunc {
	c := DefaultConfig
	c.Options = []jwt.ParseOption{jwt.WithVerify(jwa.RS256, key)}
	return JWTWithConfig(DefaultConfig)
}

func JWTWithConfig(config Config) echo.MiddlewareFunc {
	if config.Skipper == nil {
		config.Skipper = DefaultConfig.Skipper
	}

	if config.DecodeTokenFunc == nil {
		config.DecodeTokenFunc = DefaultConfig.DecodeTokenFunc
	}

	if config.TokenContextKey == "" {
		config.TokenContextKey = DefaultConfig.TokenContextKey
	}

	if config.CookieKey == "" {
		config.CookieKey = DefaultConfig.CookieKey
	}

	if config.AuthHeader == "" {
		config.AuthHeader = DefaultConfig.AuthHeader
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			path := c.Path()
			method := c.Request().Method

			if check(path, method, config.ExemptRoutes) {
				return next(c)
			}

			for _, i := range config.ExemptMethods {
				if i == c.Request().Method {
					return next(c)
				}
			}

			var encodedToken string
			cookie, err := c.Request().Cookie(config.CookieKey)
			if err == nil {
				encodedToken = cookie.String()
			}

			header := c.Request().Header.Get(config.AuthHeader)
			if header != "" {
				split := strings.Split(header, " ")
				if len(split) < 2 {
					text := "Authorization header malformed"
					return echo.NewHTTPError(http.StatusUnauthorized, text)
				}
				encodedToken = split[1]
			}

			token, err := config.DecodeTokenFunc(encodedToken, config.Options)
			if err != nil {
				if check(path, method, config.OptionalRoutes) {
					return next(c)
				}
				c.Logger().Error(err)
				return err
			}

			c.Set(config.TokenContextKey, token)

			if config.AfterDecodeFunc != nil {
				err = config.AfterDecodeFunc(c, token)
				if err != nil {
					return err
				}
			}

			return next(c)
		}
	}
}

func decodeToken(encodedToken string, options []jwt.ParseOption) (jwt.Token, error) {
	token, err := jwt.Parse([]byte(encodedToken), options...)
	if err != nil {
		if err == jwt.ErrTokenExpired() {
			return nil, echo.NewHTTPError(http.StatusUnauthorized, "token expired")
		}

		if err == jwt.ErrInvalidIssuedAt() {
			return nil, echo.NewHTTPError(http.StatusUnauthorized, "token invalid issued at")
		}

		if err == jwt.ErrTokenNotYetValid() {
			return nil, echo.NewHTTPError(http.StatusUnauthorized, "token not yet valid")
		}

		return nil, echo.NewHTTPError(http.StatusUnauthorized, "token error")
	}

	return token, nil
}

func check(path string, method string, m map[string][]string) bool {
	for k, v := range m {
		if k == path {
			for _, i := range v {
				if "*" == i || method == i {
					return true
				}
			}
		}
	}
	return false
}
