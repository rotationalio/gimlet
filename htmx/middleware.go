package htmx

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Only is a middleware that checks if the request is an HTMX request, if not it returns
// an 406 Not Acceptable error. with the annotation that the endpoint is only available
// to user interface requests. Any endpoint that uses this middleware should not
// be documented in the API documentation.
func Only(c *gin.Context) {
	if !IsHTMXRequest(c) {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{
			"success": false,
			"error":   ErrHTMXOnly.Error(),
		})
		return
	}

	// Continue handling the request.
	c.Next()
}
