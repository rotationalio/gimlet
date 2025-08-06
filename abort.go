package gimlet

import (
	"github.com/gin-gonic/gin"
	"go.rtnl.ai/x/api"
)

// Abort wraps the gin context's Abort method to determine how to respond to middleware
// requests based on the Accept header. If a JSON response is expected, it sends a
// a simple JSON error response that matches other API replies in Rotational services.
// Otherwise, it simply aborts with a text response.
func Abort(c *gin.Context, code int, err any) {
	switch c.NegotiateFormat(gin.MIMEJSON, gin.MIMEHTML, gin.MIMEPlain) {
	case gin.MIMEJSON, gin.MIMEHTML:
		c.AbortWithStatusJSON(code, api.Error(err))
	default:
		c.AbortWithError(code, &api.StatusError{StatusCode: code, Reply: api.Error(err)})
	}
}
