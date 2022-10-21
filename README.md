# echo-jwt [![Go Report Card](https://goreportcard.com/badge/github.com/alexferl/echo-jwt)](https://goreportcard.com/report/github.com/alexferl/echo-jwt) [![codecov](https://codecov.io/gh/alexferl/echo-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/alexferl/echo-jwt)

## Installing
```shell
go get github.com/alexferl/echo-jwt
```


## Using
Before using the middleware you need to generate an RSA private key (RSASSA-PKCS-v1.5 using SHA-256)
or use an existing one to verify tokens. The tokens need to have been signed by the same key!

```shell
openssl genrsa -out private-key.pem 4096
```

```go
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/alexferl/echo-jwt"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	key, err := loadPrivateKey("/path/to/private-key.pem")
	if err != nil {
		panic(fmt.Sprintf("error loading private key: %v\n", err))
	}

	e.Use(jwt.JWT(key))

	e.Logger.Fatal(e.Start(":1323"))
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
```

By default, *all* routes will require a token in the `Authorization` header or
as a cookie with the key `access_token`.

You may define some exempted routes and methods that don't require a token:
```go
e.Use(jwt.JWTWithConfig(jwt.Config{
    ExemptRoutes: map[string][]string{
        "/":          {http.MethodGet},
        "/users":     {http.MethodPost, http.MethodGet},
        "/users/:id": {http.MethodGet},
    },
    Key: key,
}))
```

### Configuration
```go
type Config struct {
    // Skipper defines a function to skip middleware.
    Skipper middleware.Skipper

    // Key defines the RSA key used to verify tokens.
    // Required.
    Key interface{}

    // ExemptRoutes defines routes and methods that don't require tokens.
    // Optional.
    ExemptRoutes map[string][]string

    // ExemptMethods defines methods that don't require tokens.
    // Optional. Defaults to [OPTIONS].
    ExemptMethods []string

    // OptionalRoutes defines routes and methods that
    // can optionally require a token.
    // Optional.
    OptionalRoutes map[string][]string

    // ParseTokenFunc defines a function used to decode tokens.
    // Optional.
    ParseTokenFunc func(string, []jwt.ParseOption) (jwt.Token, error)

    // AfterParseFunc defines a function that will run after
    // the ParseTokenFunc has successfully run.
    // Optional.
    AfterParseFunc func(echo.Context, jwt.Token) *echo.HTTPError

    // Options defines jwt.ParseOption options for parsing tokens.
    // Optional. Defaults [jwt.WithValidate(true)].
    Options []jwt.ParseOption

    // ContextKey defines the key that will be used to store the token
    // on the echo.Context when the token is successfully parsed.
    // Optional. Defaults to "token".
    ContextKey string

    // CookieKey defines the key that will be used to read the token
    // from an HTTP cookie.
    // Optional. Defaults to "access_token".
    CookieKey string

    // AuthHeader defines the HTTP header that will be used to
    // read the token from.
    // Optional. Defaults to "Authorization".
    AuthHeader string
}
```
