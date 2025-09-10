package csrf

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"go.rtnl.ai/gimlet"
)

// Parameters and headers for double-cookie submit CSRF protection.
const (
	Cookie          = "csrf_token"
	ReferenceCookie = "csrf_reference_token"
	Header          = "X-CSRF-Token"
	CookieTTL       = 1 * time.Hour
)

var (
	ErrNoCSRFReferenceCookie  = errors.New("no csrf reference cookie in request")
	ErrInvalidCSRFHeader      = errors.New("invalid csrf header: must be url encoded")
	ErrInvalidCSRFReference   = errors.New("invalid csrf reference cookie: must be url encoded")
	ErrCSRFVerification       = errors.New("csrf verification failed for request")
	ErrNaiveTokenFailed       = errors.New("naive csrf token verification failed")
	ErrNoSignedCSRFSecret     = errors.New("a secret key is required for signed csrf tokens")
	ErrShortSignedCSRFSecret  = errors.New("secret key is too short, must be 32 bytes long")
	ErrHMACVerificationFailed = errors.New("hmac verification failed for csrf token")
)

// DoubleCookie is a Cross-Site Request Forgery (CSR/XSRF) protection middleware that
// checks the presence of an X-CSRF-TOKEN header containing a cryptographically signed
// token that matches a token contained in the CSRF-TOKEN cookie in the request.
// Because of the same-origin policy, an attacker cannot access the cookies or scripts
// of the safe site, therefore the X-CSRF-TOKEN header cannot be forged, and if it is
// omitted because it is being re-posted by an attacker site then the request will be
// rejected with a 403 error. Note that this protection requires TLS to prevent MITM.
//
// See: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#alternative-using-a-double-submit-cookie-pattern
func DoubleCookie(verifier TokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie(ReferenceCookie)
		if err != nil {
			gimlet.Abort(c, http.StatusForbidden, ErrNoCSRFReferenceCookie)
			return
		}

		header := c.GetHeader(Header)
		if header, err = url.QueryUnescape(header); err != nil {
			c.Error(err)
			gimlet.Abort(c, http.StatusBadRequest, ErrInvalidCSRFHeader)
			return
		}

		if cookie == "" || header == "" {
			log.Debug().Bool("header_exists", header != "").Bool("cookie_exists", cookie != "").Msg("missing either csrf token header or reference cookie")
			gimlet.Abort(c, http.StatusForbidden, ErrCSRFVerification)
			return
		}

		// Abort if the verification fails or an error occurs.
		if secure, err := verifier.VerifyCSRFToken(cookie, header); !secure || err != nil {
			if err != nil {
				c.Error(err)
			}

			gimlet.Abort(c, http.StatusForbidden, ErrCSRFVerification)
			return
		}

		c.Next()
	}
}

// SetDoubleCookieToken uses the generator to create a CSRF token and sets two cookies:
// one for the reference that is httpOnly and secure, and another for the front-end to
// collect and add to the request header.
func SetDoubleCookieToken(c *gin.Context, generator TokenGenerator, path string, domains []string, expires time.Time) (err error) {
	// Generate a secure token
	var token string
	if token, err = generator.GenerateCSRFToken(); err != nil {
		return err
	}

	// Ensure the path is set, defaulting to root if empty
	if path == "" {
		path = "/"
	}

	// Use the default expiration if a specific time is not provided
	if expires.IsZero() {
		expires = time.Now().Add(CookieTTL)
	}

	// Compute the max age of the cookie from the expires time
	maxAge := int(time.Until(expires).Seconds()) + gimlet.CookieBuffer

	// If no domains are specified, do not specify a domain for the cookie
	if len(domains) == 0 {
		domains = append(domains, "")
	}

	// Set the CSRF cookies for each domain specified (or the current domain if none).
	for _, domain := range domains {
		secure := !gimlet.IsLocalhost(domain)

		// Set the two CSRF cookies.
		// NOTE: if one domain is a subdomain of another, the reference cookie is
		// unnecessarily duplicated, but other than increasing the data usage, it
		// should not cause an issue provided that the token is the same for both
		// reference cookies.
		c.SetCookie(ReferenceCookie, token, maxAge, path, domain, secure, true)
		c.SetCookie(Cookie, token, maxAge, path, domain, secure, false)
	}
	return nil
}

// TokenVerifier is an interface that is used for DoubleCookie session verification.
// The middleware will call the VerifyCSRFToken method with the value of the CSRF
// reference cookie and the value of the X-CSRF-Token header. If the verification
// returns false, the request will be aborted with a 403 error; if an error is returned
// the request will be aborted and the error will be logged. The middleware will only
// succeed if VerifyCSRFToken returns true and no error.
type TokenVerifier interface {
	VerifyCSRFToken(cookie, header string) (bool, error)
}

// TokenGenerator is an interface that is used to generate CSRF tokens. Tokens
// should be generated in a secure manner, such as using a cryptographic random number
// generator. Tokens may also be signed to detect tampering.
type TokenGenerator interface {
	GenerateCSRFToken() (string, error)
}

// CookieSetter is an interface that is configured to easily set both CSRF cookies
// in the gin reponse (one for the reference that is httpOnly and the other for the
// front-end to collect and add to the request header).
type CookieSetter interface {
	SetDoubleCookieToken(c *gin.Context) error
}

// TokenHandler is a convenience interface that combines all CSRF interfaces.
type TokenHandler interface {
	TokenVerifier
	TokenGenerator
	CookieSetter
}
