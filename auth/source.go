package auth

import (
	"errors"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
)

var (
	ErrNoAuthenticationSource      = errors.New("no authentication source found on request")
	ErrInvalidAuthenticationSource = errors.New("invalid authentication source type")
)

// AuthenticationSource identifies the credential that ultimately authenticated a
// request.
type AuthenticationSource uint8

const (
	AuthenticationSourceUnknown AuthenticationSource = iota
	AuthenticationSourceBearer
	AuthenticationSourceCookie
)

func (s AuthenticationSource) String() string {
	switch s {
	case AuthenticationSourceBearer:
		return "bearer"
	case AuthenticationSourceCookie:
		return "cookie"
	default:
		return "unknown"
	}
}

// Retrieves the credential source recorded by the Authenticate middleware.
func GetAuthenticationSource(c *gin.Context) (AuthenticationSource, error) {
	value, exists := gimlet.Get(c, gimlet.KeyAuthenticationSource)
	if !exists {
		return AuthenticationSourceUnknown, ErrNoAuthenticationSource
	}

	source, ok := value.(AuthenticationSource)
	if !ok {
		return AuthenticationSourceUnknown, ErrInvalidAuthenticationSource
	}
	return source, nil
}
