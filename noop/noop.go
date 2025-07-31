package noop

import "github.com/gin-gonic/gin"

// A No-Operation Middleware.
func Noop() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Do nothing, just pass the request through.
		c.Next()
	}
}
