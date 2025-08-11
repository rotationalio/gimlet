package quarterdeck

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"go.rtnl.ai/gimlet/auth"
	"go.rtnl.ai/ulid"
	"go.rtnl.ai/x/api"
)

const (
	// Default timeout for synchronization requests to Quarterdeck.
	SyncTimeout = 20 * time.Second

	// Default interval for synchronization of JWKS and OpenID configuration if not
	// specified by the Expires header.
	SyncInterval = 1 * time.Hour
)

var (
	ErrNoLoginURL = errors.New("no login URL specified or authentication endpoint set in OIDC discovery data")
)

// Quarterdeck implements the Authenticator and Reauthenticator interface for the
// Authenticate middleware. It uses the JWKS endpoint exposed by Quarterdeck to verify
// access tokens and extract claims and the Quarterdeck API to reauthenticate
// valid refresh tokens.
type Quarterdeck struct {
	sync.RWMutex

	// Data fetched from Quarterdeck
	keys   *jose.JSONWebKeySet
	config *OpenIDConfiguration
	parser *jwt.Parser

	// Endpoints for Quarterdeck required data
	jwksURL   string
	configURL string

	// User-specified configuration
	audience       string
	issuer         string
	signingMethods []string
	loginURL       *LoginURL

	// HTTP requests and Cache Control
	client  *http.Client
	etag    map[string]string    // ETag for caching purposes
	expires map[string]time.Time // Expiration time for caching purposes
}

var _ auth.Authenticator = (*Quarterdeck)(nil)

func New(configURL, audience string, opts ...Option) (qd *Quarterdeck, err error) {
	qd = &Quarterdeck{
		jwksURL:   "",
		configURL: configURL,
		audience:  audience,
		issuer:    "",
		loginURL:  &LoginURL{},
		etag:      make(map[string]string),
		expires:   make(map[string]time.Time),
	}

	for _, opt := range opts {
		if err := opt(qd); err != nil {
			return nil, err
		}
	}

	if qd.client == nil {
		qd.client = &http.Client{
			Transport:     nil,
			CheckRedirect: nil,
			Timeout:       30 * time.Second,
		}

		if qd.client.Jar, err = cookiejar.New(nil); err != nil {
			return nil, fmt.Errorf("could not create cookiejar: %w", err)
		}
	}

	// Attempt a synchronization of the JWKS and OpenID configuration
	if err = qd.Sync(); err != nil {
		return nil, err
	}

	// Start the synchronization process in a goroutine
	qd.Run()
	return qd, nil
}

// Implements the Authenticator interface to verify access tokens with the JWKS keys
// fetched from the Quarterdeck server.
func (s *Quarterdeck) Verify(accessToken string) (claims *auth.Claims, err error) {
	s.RLock()
	defer s.RUnlock()

	var token *jwt.Token
	if token, err = s.parser.ParseWithClaims(accessToken, &auth.Claims{}, s.GetKey); err != nil {
		return nil, err
	}

	var ok bool
	if claims, ok = token.Claims.(*auth.Claims); ok && token.Valid {
		return claims, nil
	}

	// I haven't figured out a test that will allow us to reach this case; if you pass
	// in a token with a different type of claims, it will return an empty auth.Claims.
	return nil, auth.ErrUnparsableClaims
}

func (s *Quarterdeck) GetKey(token *jwt.Token) (key interface{}, err error) {
	// Fetch the kid from the header
	kid, ok := token.Header["kid"]
	if !ok {
		return nil, auth.ErrNoKeyID
	}

	// Parse the kid
	var keyID ulid.ULID
	if keyID, err = ulid.Parse(kid.(string)); err != nil {
		return nil, fmt.Errorf("could not parse kid: %w", err)
	}

	if keyID.IsZero() {
		return nil, auth.ErrInvalidKeyID
	}

	// Fetch the key from the list of managed keys
	keys := s.keys.Key(keyID.String())
	if len(keys) == 0 {
		return nil, auth.ErrUnknownSigningKey
	}

	// If we have multiple keys, return the first one; this should not happen
	if len(keys) > 1 {
		log.Warn().Str("keyID", keyID.String()).
			Msg("multiple signing keys found for kid")
	}

	return keys[0].Key, nil
}

// Implements the Unauthenticator interface to redirect to the login URL when
// authentication fails.
func (s *Quarterdeck) NotAuthorized(c *gin.Context) error {
	var loginURL string
	if loginURL = s.loginURL.Location(c); loginURL == "" {
		return ErrNoLoginURL
	}

	if IsHTMXRequest(c) {
		Redirect(c, http.StatusSeeOther, loginURL)
		c.Abort()
		return nil
	}

	// Content Negotiation
	switch accept := c.NegotiateFormat(binding.MIMEJSON, binding.MIMEHTML); accept {
	case binding.MIMEJSON:
		c.AbortWithStatusJSON(http.StatusUnauthorized, api.Error(auth.ErrAuthRequired))
	case binding.MIMEHTML:
		c.Redirect(http.StatusSeeOther, loginURL)
		c.Abort()
	default:
		return fmt.Errorf("unhandled negotiated content type %q", accept)
	}

	return nil
}

func (s *Quarterdeck) Run() {
	// Get the expiration time for the JWKS
	wait := SyncInterval
	if expires, ok := s.Expires(s.jwksURL); ok {
		wait = time.Until(expires)
	}

	// Synchronize then schedule the next synchronization
	time.AfterFunc(wait, func() {
		s.Sync()
		s.Run() // Restart the synchronization process
	})
}

// Synchronizes the JWKS and OpenID configuration from Quarterdeck, respecting the
// cache-control headers and ETag for caching purposes.
func (s *Quarterdeck) Sync() (err error) {
	s.Lock()
	defer s.Unlock()

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), SyncTimeout)
	defer cancel()

	// Fetch the OpenID configuration from Quarterdeck
	if expires, ok := s.expires[s.configURL]; !ok || now.After(expires) {
		if s.config, err = s.Config(ctx); err != nil {
			if !errors.Is(err, auth.ErrNotModified) {
				// If the error is not a 304 Not Modified, return it
				return fmt.Errorf("could not fetch OpenID configuration: %w", err)
			}
		}

		// Update the local configuration from the fetched configuration
		if s.config != nil {
			// Always update the JWKS URL if it changed
			if s.jwksURL != s.config.JWKSURI {
				delete(s.expires, s.jwksURL)
				s.jwksURL = s.config.JWKSURI
			}

			// If the user did not specify a login URL, use the one from the configuration
			s.loginURL.Update(s.config.AuthorizationEP)
		}
	}

	// Fetch the JWKS from Quarterdeck
	if expires, ok := s.expires[s.jwksURL]; !ok || now.After(expires) {
		if s.keys, err = s.JWKS(ctx); err != nil {
			if !errors.Is(err, auth.ErrNotModified) {
				// If the error is not a 304 Not Modified, return it
				return fmt.Errorf("could not fetch JWKS: %w", err)
			}
		}
	}

	// Create the JWT parser
	opts := []jwt.ParserOption{
		jwt.WithAudience(s.audience),
	}

	// If the user specified the issuer, use it or the issuer specified by the OpenID configuration
	if s.issuer != "" {
		opts = append(opts, jwt.WithIssuer(s.issuer))
	} else if s.config != nil && s.config.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(s.config.Issuer))
	}

	// If the user specified signing methods, use them or the ones specified by the OpenID configuration
	if len(s.signingMethods) > 0 {
		opts = append(opts, jwt.WithValidMethods(s.signingMethods))
	} else if s.config != nil && len(s.config.IDTokenSigningAlgValues) > 0 {
		opts = append(opts, jwt.WithValidMethods(s.config.IDTokenSigningAlgValues))
	}

	s.parser = jwt.NewParser(opts...)
	return nil
}

func (s *Quarterdeck) Expires(url string) (expires time.Time, ok bool) {
	s.RLock()
	defer s.RUnlock()

	expires, ok = s.expires[url]
	return expires, ok
}

//===========================================================================
// Quarterdeck Interaction
//===========================================================================

// Returns the OpenID configuration by performing a GET request to Quarterdeck.
func (s *Quarterdeck) Config(ctx context.Context) (out *OpenIDConfiguration, err error) {
	if s.configURL == "" {
		return nil, auth.ErrMissingConfigURL
	}

	var req *http.Request
	if req, err = s.NewRequest(ctx, s.configURL); err != nil {
		return nil, err
	}

	if _, err = s.Do(req, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// Returns the JWKS (JSON Web Key Set) by performing a GET request to Quarterdeck.
func (s *Quarterdeck) JWKS(ctx context.Context) (out *jose.JSONWebKeySet, err error) {
	if s.jwksURL == "" {
		return nil, auth.ErrMissingJWKSURL
	}

	var req *http.Request
	if req, err = s.NewRequest(ctx, s.jwksURL); err != nil {
		return nil, err
	}

	if _, err = s.Do(req, &out); err != nil {
		return nil, err
	}

	return out, nil
}
