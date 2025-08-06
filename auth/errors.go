package auth

import "errors"

var (
	ErrMissingConfigURL  = errors.New("a configuration URL to the openid provider is required")
	ErrMissingJWKSURL    = errors.New("no jwks uri specified or found in the openid configuration")
	ErrNotModified       = errors.New("the requested resource has not been modified")
	ErrUnparsableClaims  = errors.New("the claims in the token could not be parsed as gimlet auth claims")
	ErrUnknownSigningKey = errors.New("unknown signing key")
	ErrNoKeyID           = errors.New("token does not have kid in header")
	ErrInvalidKeyID      = errors.New("invalid key id")
)
