# echo-jwt [![Go Report Card](https://goreportcard.com/badge/github.com/alexferl/echo-jwt)](https://goreportcard.com/report/github.com/alexferl/echo-jwt) [![codecov](https://codecov.io/gh/alexferl/echo-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/alexferl/echo-jwt)

A [JWT](https://jwt.io/) middleware for the [Echo](https://github.com/labstack/echo) framework using [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

## Motivation
You might wonder, why not use the JWT middleware that ships with Echo? The reason is that is uses the [golang-jwt/jwt](https://github.com/golang-jwt/jwt) library which, although a good library, doesn't implement every JWT features while [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) is the [most complete](https://jwt.io/libraries?language=Go) implementation as of this writing. I think echo-jwt also has better defaults, like `RS256` as the default signing method and is also more flexbile in what parsing options you can pass to the token verification function through the `Options` config. I think other features like `ExemptRoutes`, `ExemptMethods` and `OptionalRoutes` are useful features that most developers would want to use without having to implement them themselves.

## Installing
```shell
go get github.com/alexferl/echo-jwt
```

## Using
Before using the middleware you need to generate an RSA private key (RSASSA-PKCS-v1.5 using SHA-256) to
sign and verify the tokens.

```shell
openssl genrsa -out private-key.pem 4096
```

Code example:
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
	"time"

	"github.com/alexferl/echo-jwt"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwx "github.com/lestrrat-go/jwx/v2/jwt"
)

var privateKey *rsa.PrivateKey

func main() {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		t := c.Get("token").(jwx.Token)
		return c.JSON(http.StatusOK, t)
	})

	e.POST("/login", func(c echo.Context) error {
		builder := jwx.NewBuilder().
			Subject("1").
			Issuer("http://localhost:1323").
			IssuedAt(time.Now()).
			NotBefore(time.Now()).
			Expiration(time.Now().Add(time.Minute*10)).
			Claim("name", c.QueryParam("name"))

		token, err := builder.Build()
		if err != nil {
			panic(fmt.Sprintf("failed building token: %v\n", err))
		}

		signed, err := jwx.Sign(token, jwx.WithKey(jwa.RS256, privateKey))
		if err != nil {
			panic(fmt.Sprintf("failed signing token: %v\n", err))
		}

		return c.JSON(http.StatusOK, map[string]string{"access_token": string(signed)})
	})

	key, err := loadPrivateKey("/path/to/private-key.pem")
	if err != nil {
		panic(fmt.Sprintf("failed loading private key: %v\n", err))
	}
	privateKey = key

	e.Use(jwt.JWT(key))

	e.Logger.Fatal(e.Start("localhost:1323"))
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

Getting a token:
```shell
curl -X POST http://localhost:1323/login\?name\=alex
{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj..."}
```

Using a token:
```shell
curl http://localhost:1323/ -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj...'
{"exp":1666320946,"iat":1666320346,"iss":"http://localhost:1323","name":"name","nbf":1666320346,"sub":"1"}
```

### Exempt routes
By default, *all* routes except `POST /login` will require a token in
the `Authorization` header or as a cookie with the key `access_token`.

You may define some additional exempted routes and methods that don't require a token:
```go
e.Use(jwt.JWTWithConfig(jwt.Config{
    ExemptRoutes: map[string][]string{
        "/":          {http.MethodGet},
        "/login":     {http.MethodPost},
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
    // Optional. Defaults to /login [POST].
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

    // AuthScheme defines the authorization scheme in the AuthHeader.
    // Optional. Defaults to "Bearer".
    AuthScheme string
}
```
