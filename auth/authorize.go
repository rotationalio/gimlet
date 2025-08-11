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
//
// NOTE: pass permissions as strings or fmt.Stringer implementations.
func Authorize(permissions ...any) gin.HandlerFunc {
	// Convert the permissions to a slice of strings.
	perms := make([]string, len(permissions))
	for i, p := range permissions {
		var perm string
		switch v := p.(type) {
		case string:
			perm = v
		case fmt.Stringer:
			perm = v.String()
		default:
			perm = fmt.Sprintf("%v", v)
		}
		perms[i] = perm
	}

	return func(c *gin.Context) {
		claims, err := GetClaims(c)
		if err != nil {
			c.Error(err)
			gimlet.Abort(c, http.StatusUnauthorized, ErrNoAuthorization)
			return
		}

		if !claims.HasAllPermissions(perms...) {
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
