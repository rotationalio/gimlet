package csrf

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/ulid"
)

// NewTokenHandler returns a CSRF token handler that generates and verifies CSRF tokens.
// If the secret is specified (not nil) then a signed CSRF token handler is returned,
// otherwise a naive CSRF token handler is returned.
func NewTokenHandler(cookieTTL time.Duration, path string, domains []string, secret []byte) (TokenHandler, error) {
	// Deduplicate and normalize domains
	domains = gimlet.CookieDomains(domains...)

	if secret != nil {
		handler := &SignedCSRFTokens{
			CookieTTL:    cookieTTL,
			CookiePath:   path,
			CookieDomain: domains,
		}
		if err := handler.SetSecret(secret); err != nil {
			return nil, err
		}
		return handler, nil
	}

	return &NaiveCSRFTokens{
		CookieTTL:    cookieTTL,
		CookiePath:   path,
		CookieDomain: domains,
	}, nil
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
	if err != nil || len(cookieBytes) != 64 {
		return false, ErrInvalidCSRFReference
	}

	headerBytes, err := base64.URLEncoding.DecodeString(header)
	if err != nil || len(headerBytes) != 64 {
		return false, ErrInvalidCSRFHeader
	}

	// First check if cookie and header are identical (otherwise HMAC validation is not needed)
	if !bytes.Equal(cookieBytes, headerBytes) {
		return false, nil
	}

	// No need to verify the signature of the cookie if they are identical; just ensure
	// that the header has a valid signature using the internal secret.
	if _, err = s.verifySignature(headerBytes); err != nil {
		return false, err
	}

	// Reference cookie and header are identical, and the header is signed correctly.
	return true, nil
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

	if err := SetDoubleCookieToken(c, s, s.CookiePath, s.CookieDomain, expires); err != nil {
		return err
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

	if err := SetDoubleCookieToken(c, n, n.CookiePath, n.CookieDomain, expires); err != nil {
		return err
	}
	return nil
}
