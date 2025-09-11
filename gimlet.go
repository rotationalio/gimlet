package gimlet

import (
	"net/url"
	"regexp"
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
	domain = CookieDomain(domain)
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

var (
	domainRE = regexp.MustCompile(`^(.+:)?//(.+)$`)
)

// Converts a URL to an appropriate cookie domain by removing the scheme and path
// components if necessary as well as any port information. If the URL is not parseable
// the original domain is returned.
func CookieDomain(domain string) string {
	if domain == "" {
		return ""
	}

	uri, err := url.Parse(domain)
	if err != nil {
		return domain
	}

	if hostname := uri.Hostname(); hostname != "" {
		return hostname
	}

	// Attempt a reparse with prefixing
	if !domainRE.MatchString(domain) {
		return CookieDomain("//" + domain)
	}

	// Otherwise just return the original domain
	return domain
}

// Normalize and deduplicate multiple cookie domains
func CookieDomains(domain ...string) []string {
	cookieDomains := make(map[string]struct{})
	for _, d := range domain {
		cookieDomains[CookieDomain(d)] = struct{}{}
	}

	i := 0
	domain = domain[:len(cookieDomains)]
	for cd := range cookieDomains {
		domain[i] = cd
		i++
	}

	return domain
}

// Returns only the root domains from a list of domains, removing any subdomains.
// TODO: this is a suffix-based implementation but should use a public suffix list.
func RootDomains(domains []string) []string {
	roots := make([]string, 0, len(domains))
	for i, d := range domains {
		// If this is a subdomain of any other domain (e.g. one of the other domains
		// is a suffix of this domain with a dot before it), do not include it in the
		// roots list.
		isSubdomain := false
		for j, od := range domains {
			if i != j && (strings.HasSuffix(d, "."+od)) {
				isSubdomain = true
				break
			}

			if i != j && d == od && i < j {
				// Deduplicate identical domains
				isSubdomain = true
				break
			}
		}

		if !isSubdomain {
			roots = append(roots, d)
		}
	}
	return roots
}
