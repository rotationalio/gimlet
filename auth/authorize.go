package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
)

var (
	ErrNoAuthorization = errors.New("no authorization claims found on request")
	ErrNotPermitted    = errors.New("request does not have the required permissions")
)

// Authorize is a middleware that requires specific permissions in an authenticated
// user's claims. If the request is unauthenticated, the middleware returns a 401
// Unauthorized response. If the claims have insufficient permissions, the middleware
// returns a 403 Forbidden response. The Authorize middleware must be chained following
// the Authenticate middleware.
func Authorize(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := GetClaims(c)
		if err != nil {
			c.Error(err)
			gimlet.Abort(c, http.StatusUnauthorized, ErrNoAuthorization)
			return
		}

		if !claims.HasAllPermissions(permissions...) {
			gimlet.Abort(c, http.StatusForbidden, ErrNotPermitted)
			return
		}

		c.Next()
	}
}

func GetClaims(c *gin.Context) (*Claims, error) {
	val, exists := gimlet.Get(c, gimlet.KeyUserClaims)
	if !exists {
		return nil, ErrNoAuthorization
	}

	claims, ok := val.(*Claims)
	if !ok {
		return nil, fmt.Errorf("could not handle claims of type %T", val)
	}

	return claims, nil
}
