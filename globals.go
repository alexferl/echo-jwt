package jwt

import (
	"net/http"
)

var (
	ErrAuthorizationHeader        = "authorization header malformed"
	ErrAuthorizationHeaderStatus  = http.StatusUnauthorized
	ErrAuthorizationScheme        = "authorization scheme not supported"
	ErrAuthorizationSchemeStatus  = http.StatusUnauthorized
	ErrBodyMissingKey             = "body is missing refresh token key"
	ErrBodyMissingKeyStatus       = http.StatusUnprocessableEntity
	ErrMethodNotAllowed           = "method not allowed"
	ErrMethodNotAllowedStatus     = http.StatusMethodNotAllowed
	ErrRequestMalformed           = "request malformed"
	ErrRequestMalformedStatus     = http.StatusBadRequest
	ErrRouteNotFound              = "route not found"
	ErrRouteNotFoundStatus        = http.StatusNotFound
	ErrTokenExpired               = "token is expired"
	ErrTokenExpiredStatus         = http.StatusUnauthorized
	ErrTokenInvalid               = "token is invalid"
	ErrTokenInvalidStatus         = http.StatusUnauthorized
	ErrTokenInvalidIssuedAt       = "token has invalid issued at"
	ErrTokenInvalidIssuedAtStatus = http.StatusUnauthorized
	ErrTokenNotYetValid           = "token is not yet valid"
	ErrTokenNotYetValidStatus     = http.StatusUnauthorized
)
