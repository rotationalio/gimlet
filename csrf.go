package gimlet

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"go.rtnl.ai/ulid"
)

// Parameters and headers for double-cookie submit CSRF protection.
const (
	CSRFCookie          = "csrf_token"
	CSRFReferenceCookie = "csrf_reference_token"
	CSRFHeader          = "X-CSRF-Token"
	CSRFCookieTTL       = 1 * time.Hour
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
func DoubleCookie(verifier CSRFTokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie(CSRFReferenceCookie)
		if err != nil {
			Abort(c, http.StatusForbidden, ErrNoCSRFReferenceCookie)
			return
		}

		header := c.GetHeader(CSRFHeader)
		if header, err = url.QueryUnescape(header); err != nil {
			c.Error(err)
			Abort(c, http.StatusBadRequest, ErrInvalidCSRFHeader)
			return
		}

		if cookie == "" || header == "" {
			log.Debug().Bool("header_exists", header != "").Bool("cookie_exists", cookie != "").Msg("missing either csrf token header or reference cookie")
			Abort(c, http.StatusForbidden, ErrCSRFVerification)
			return
		}

		// Abort if the verification fails or an error occurs.
		if secure, err := verifier.VerifyCSRFToken(cookie, header); !secure || err != nil {
			if err != nil {
				c.Error(err)
			}

			Abort(c, http.StatusForbidden, ErrCSRFVerification)
			return
		}

		c.Next()
	}
}

// SetDoubleCookieToken uses the generator to create a CSRF token and sets two cookies:
// one for the reference that is httpOnly and secure, and another for the front-end to
// collect and add to the request header.
func SetDoubleCookieToken(c *gin.Context, generator CSRFTokenGenerator, path, domain string, expires time.Time) (err error) {
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
		expires = time.Now().Add(CSRFCookieTTL)
	}

	// Compute the max age of the cookie from the expires time
	maxAge := int(time.Until(expires).Seconds()) + cookieBuffer
	secure := !IsLocalhost(domain)

	// Set the two CSRF cookies.
	c.SetCookie(CSRFReferenceCookie, token, maxAge, path, domain, secure, true)
	c.SetCookie(CSRFCookie, token, maxAge, path, domain, secure, false)
	return nil
}

// CSRFTokenVerifier is an interface that is used for DoubleCookie session verification.
// The middleware will call the VerifyCSRFToken method with the value of the CSRF
// reference cookie and the value of the X-CSRF-Token header. If the verification
// returns false, the request will be aborted with a 403 error; if an error is returned
// the request will be aborted and the error will be logged. The middleware will only
// succeed if VerifyCSRFToken returns true and no error.
type CSRFTokenVerifier interface {
	VerifyCSRFToken(cookie, header string) (bool, error)
}

// CSRFTokenGenerator is an interface that is used to generate CSRF tokens. Tokens
// should be generated in a secure manner, such as using a cryptographic random number
// generator. Tokens may also be signed to detect tampering.
type CSRFTokenGenerator interface {
	GenerateCSRFToken() (string, error)
}

// CSRFCookieSetter is an interface that is configured to easily set both CSRF cookies
// in the gin reponse (one for the reference that is httpOnly and the other for the
// front-end to collect and add to the request header).
type CSRFCookieSetter interface {
	SetDoubleCookieToken(c *gin.Context) error
}

// CSRFTokenHandler is a convenience interface that combines all CSRF interfaces.
type CSRFTokenHandler interface {
	CSRFTokenVerifier
	CSRFTokenGenerator
	CSRFCookieSetter
}

//===========================================================================
// Signed CSRF Double Cookie Tokens (recommended)
//===========================================================================

// SignedCSRFTokens generates signed double submit cookies using HMAC with a secret key.
// The session ID is a ULID appended with a random nonce, and the signature is computed
// securely. Verification is done by checking the signature, then parsing the session ID
// and comparing the two session IDs. Verification fails if the signature is invalid,
// not a ULID, or if the session IDs do not match.
//
// See: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#signed-double-submit-cookie-recommended
type SignedCSRFTokens struct {
	sync.RWMutex

	// Specify the max age of the CSRF cookie (default is 1 hour).
	CookieTTL time.Duration

	// Path for the CSRF cookie (default is "/").
	CookiePath string

	// Domain(s) for the CSRF cookie (default is empty which means the cookie
	// is valid for the current domain).
	CookieDomain []string

	// Secret key used to sign the CSRF tokens.
	secret []byte
}

// SetSecret sets the secret key used to sign the CSRF tokens. If the secret is nil or
// empty, a new random secret will be generated. Note that if a secret is changed, it
// will invalidate any previously generated tokens (a good way to cancel all active
// sessions). A secret must be set before generating or verifying tokens.
//
// NOTE: an ideal secret should be 32 or 64 bytes long, any shorter will return an error
// and any larger will be hashed by the HMAC algorithm into 64 bytes and does not
// provide any additional security (and will cost some performance).
func (s *SignedCSRFTokens) SetSecret(secret []byte) error {
	s.Lock()
	defer s.Unlock()

	// If the secret is empty, generate a new random secret.
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
	}

	// If the secret is too short, return an error.
	if len(secret) < 32 {
		return ErrShortSignedCSRFSecret
	}

	s.secret = secret
	return nil
}

// Generates a CSRF token by creating a secure ULID, then signs the result with the
// secret key. The token is the base64-encoded string of the ULID and the signature.
// This method returns an error if the secret is not set or if token generation fails.
func (s *SignedCSRFTokens) GenerateCSRFToken() (_ string, err error) {
	s.RLock()
	defer s.RUnlock()

	if len(s.secret) == 0 {
		return "", ErrNoSignedCSRFSecret
	}

	// Generate a ULID and a random nonce
	sessionID := ulid.MakeSecure()
	nonce := make([]byte, 16)

	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	// Compute the HMAC signature using the secret key
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(sessionID[:])
	mac.Write(nonce)

	// Combine the sessionID, nonce, and signature into a single token
	token := make([]byte, 64)
	copy(token[:16], sessionID[:])
	copy(token[16:32], nonce)
	copy(token[32:64], mac.Sum(nil))

	return base64.URLEncoding.EncodeToString(token), nil
}

// Verifies that the CSRF token in the cookie matches the one in the header by checking
// the HMAC signature of both the cookie and the header values. If the signature is
// valid with respect to the secret key, and the session IDs match, it returns true.
func (s *SignedCSRFTokens) VerifyCSRFToken(cookie, header string) (bool, error) {
	s.RLock()
	defer s.RUnlock()

	// Decode the cookie and header values
	cookieBytes, err := base64.URLEncoding.DecodeString(cookie)
	if err != nil {
		return false, ErrInvalidCSRFReference
	}

	headerBytes, err := base64.URLEncoding.DecodeString(header)
	if err != nil {
		return false, ErrInvalidCSRFHeader
	}

	// First check if cookie and header are identical (otherwise HMAC validation is not needed)
	if !bytes.Equal(cookieBytes, headerBytes) {
		return false, nil
	}

	cookieULID, err := s.verifySignature(cookieBytes)
	if err != nil {
		return false, err
	}

	headerULID, err := s.verifySignature(headerBytes)
	if err != nil {
		return false, err
	}

	// Secondary double-check is probably unnecessary
	return cookieULID.Equals(headerULID), nil
}

// Returns the ULID session ID from the CSRF token or an error if the token is not
// signed correctly or is not a valid ULID. This method is not thread safe.
func (s *SignedCSRFTokens) verifySignature(token []byte) (ulid.ULID, error) {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(token[:32])
	signature := mac.Sum(nil)
	if !hmac.Equal(signature, token[32:]) {
		return ulid.ULID{}, ErrHMACVerificationFailed
	}
	return ulid.ULID(token[:16]), nil
}

// Uses the generator to create a CSRF token and sets two cookies: the httpOnly CSRF
// reference cookie and the CSRF token for the front-end to collect and add to the
// request header. The cookies are set with the expiration, path, and domain(s)
// specified. An error is returned if the secret is not set or if the token generation
// fails. This method read-locks the generator to ensure that the CSRF tokens are
// generated with the same secret across all domains (which causes two read locks).
func (s *SignedCSRFTokens) SetDoubleCookieToken(c *gin.Context) error {
	s.RLock()
	defer s.RUnlock()

	var expires time.Time
	if s.CookieTTL > 0 {
		expires = time.Now().Add(s.CookieTTL)
	}

	if len(s.CookieDomain) == 0 {
		if err := SetDoubleCookieToken(c, s, s.CookiePath, "", expires); err != nil {
			return err
		}
		return nil
	}

	// Note: each generate will cause a double read lock; but that's fine since it
	// ensures all domains have CSRF tokens set signed with the same secret.
	for _, domain := range s.CookieDomain {
		if err := SetDoubleCookieToken(c, s, s.CookiePath, domain, expires); err != nil {
			return err
		}
	}

	return nil
}

//===========================================================================
// Naive CSRF Double Cookie Tokens (unsigned, discouraged)
//===========================================================================

// NaiveCSRFTokens is a simple implementation of CSRF token generation and verification
// that does not use signing. It generates a random token and verifies it by comparing
// the cookie and header values directly. The OWASP CSRF prevention cheat sheet
// discourages this method as it does not protect against all types of CSRF attacks.
//
// See: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#naive-double-submit-cookie-pattern-discouraged
type NaiveCSRFTokens struct {
	// Specify the max age of the CSRF cookie (default is 1 hour).
	CookieTTL time.Duration

	// Path for the CSRF cookie (default is "/").
	CookiePath string

	// Domain(s) for the CSRF cookie (default is empty which means the cookie
	// is valid for the current domain).
	CookieDomain []string

	seed     []byte
	initSeed sync.Once
}

// Randomly generates a CSRF session token using crypto/rand and returns it as a
// base64-encoded string. There is no signing for verification, so this method is
// discouraged as it doesn't not protect against all types of CSRF attacks.
func (n *NaiveCSRFTokens) GenerateCSRFToken() (_ string, err error) {
	n.initSeed.Do(func() {
		n.seed = make([]byte, 16)
		_, err = rand.Read(n.seed)

	})

	if err != nil {
		return "", err
	}

	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	sig := sha256.New()
	sig.Write(n.seed)
	sig.Write(nonce)

	return base64.URLEncoding.EncodeToString(sig.Sum(nil)), nil
}

// Naive verification is a simple string comparison of the CSRF cookie vs the header.
// An error is returned if either the cookie or header is empty.
func (n *NaiveCSRFTokens) VerifyCSRFToken(cookie, header string) (bool, error) {
	if cookie == "" || header == "" {
		return false, ErrNaiveTokenFailed
	}
	return cookie == header, nil
}

// Uses the generator to create a CSRF token and sets two cookies: the httpOnly CSRF
// reference cookie and the CSRF token for the front-end to collect and add to the
// request header. The cookies are set with the expiration, path, and domain(s) specified.
func (n *NaiveCSRFTokens) SetDoubleCookieToken(c *gin.Context) error {
	var expires time.Time
	if n.CookieTTL > 0 {
		expires = time.Now().Add(n.CookieTTL)
	}

	if len(n.CookieDomain) == 0 {
		if err := SetDoubleCookieToken(c, n, n.CookiePath, "", expires); err != nil {
			return err
		}
		return nil
	}

	// NOTE: each domain will get a different CSRF token, but it shouldn't cause an issue.
	for _, domain := range n.CookieDomain {
		if err := SetDoubleCookieToken(c, n, n.CookiePath, domain, expires); err != nil {
			return err
		}
	}

	return nil
}
