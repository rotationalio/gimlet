package gimlet

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	localhost    = "localhost"
	localTLD     = ".local"
	CookieBuffer = 60
	CookieTTL    = 1 * time.Hour
)

func SetCookie(c *gin.Context, name, value, path, domain string, expires time.Time, httpOnly bool) {
	if expires.IsZero() {
		expires = time.Now().Add(CookieTTL)
	}

	// Compute the max age of the cookie from the expires time
	maxAge := int(time.Until(expires).Seconds()) + CookieBuffer

	// Secure should be true unless the domain is localhost or ends with .local
	secure := !IsLocalhost(domain)

	// Ensure the path is set, defaulting to root if empty
	if path == "" {
		path = "/"
	}

	// Set the cookie on the request with the specified parameters
	c.SetCookie(name, value, maxAge, path, domain, secure, httpOnly)
}

func ClearCookie(c *gin.Context, name, path, domain string, httpOnly bool) {
	// Secure should be true unless the domain is localhost or ends with .local
	secure := !IsLocalhost(domain)

	// Ensure the path is set, defaulting to root if empty
	if path == "" {
		path = "/"
	}

	// Clear the cookie by setting its value to an empty string and max age to -1
	c.SetCookie(name, "", -1, path, domain, secure, httpOnly)
}

func IsLocalhost(domain string) bool {
	return domain == localhost || strings.HasSuffix(domain, localTLD)
}
