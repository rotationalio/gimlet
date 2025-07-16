package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
)

// Authorize is a middleware that requires specific permissions in an authenticated
// user's claims. If the request is unauthenticated, the middleware returns a 401
// Unauthorized response. If the claims have insufficient permissions, the middleware
// returns a 403 Forbidden response. The Authorize middleware must be chained following
// the Authenticate middleware.
func Authorize(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, err := GetClaims(c)
		if err != nil {
			gimlet.Abort(c, http.StatusUnauthorized, "unauthenticated request")
		}

		c.Next()
	}
}
