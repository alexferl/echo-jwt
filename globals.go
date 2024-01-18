package jwt

import (
	"net/http"
)

var (
	ErrAuthorizationHeader        = "authorization header malformed"
	ErrAuthorizationHeaderStatus  = http.StatusUnauthorized
	ErrAuthorizationScheme        = "authorization scheme not supported"
	ErrAuthorizationSchemeStatus  = http.StatusUnauthorized
	ErrBodyMissingKey             = "body missing refresh token key"
	ErrBodyMissingKeyStatus       = http.StatusUnprocessableEntity
	ErrMethodNotAllowed           = "method not allowed"
	ErrMethodNotAllowedStatus     = http.StatusMethodNotAllowed
	ErrRequestMalformed           = "request malformed"
	ErrRequestMalformedStatus     = http.StatusBadRequest
	ErrRouteNotFound              = "route not found"
	ErrRouteNotFoundStatus        = http.StatusNotFound
	ErrTokenExpired               = "token expired"
	ErrTokenExpiredStatus         = http.StatusUnauthorized
	ErrTokenInvalid               = "token invalid"
	ErrTokenInvalidStatus         = http.StatusUnauthorized
	ErrTokenInvalidIssuedAt       = "token invalid issued at"
	ErrTokenInvalidIssuedAtStatus = http.StatusUnauthorized
	ErrTokenNotYetValid           = "token not yet valid"
	ErrTokenNotYetValidStatus     = http.StatusUnauthorized
)
