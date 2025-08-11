package quarterdeck

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// HTMX Request Headers
const (
	HXRequest  = "HX-Request"
	HXRedirect = "HX-Redirect"
)

// Redirect determines if the request is an HTMX request, if so, it sets the HX-Redirect
// header and returns a 204 no content to allow HTMX to handle the redirect. Otherwise
// it sets the code and issues a normal gin redirect with the location in the headers.
func Redirect(c *gin.Context, code int, location string) {
	if IsHTMXRequest(c) {
		c.Header(HXRedirect, location)
		c.Status(http.StatusNoContent)
		return
	}

	c.Redirect(code, location)
}

// Returns true if the request contains the HXRequest header.
func IsHTMXRequest(c *gin.Context) bool {
	return strings.ToLower(c.GetHeader(HXRequest)) == "true"
}
