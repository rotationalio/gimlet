package quarterdeck

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"go.rtnl.ai/gimlet/auth"
	"go.rtnl.ai/ulid"
)

var (
	ErrMissingConfigURL  = errors.New("a configuration URL to the openid provider is required")
	ErrMissingJWKSURL    = errors.New("no jwks uri specified or found in the openid configuration")
	ErrNotModified       = errors.New("the requested resource has not been modified")
	ErrUnparsableClaims  = errors.New("the claims in the token could not be parsed as gimlet auth claims")
	ErrUnknownSigningKey = errors.New("unknown signing key")
	ErrNoKeyID           = errors.New("token does not have kid in header")
	ErrInvalidKeyID      = errors.New("invalid key id")
)

const (
	// Default timeout for synchronization requests to Quarterdeck.
	SyncTimeout = 20 * time.Second

	// Default interval for synchronization of JWKS and OpenID configuration if not
	// specified by the Expires header.
	SyncInterval = 1 * time.Hour
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
	return nil, ErrUnparsableClaims
}

func (s *Quarterdeck) GetKey(token *jwt.Token) (key interface{}, err error) {
	// Fetch the kid from the header
	kid, ok := token.Header["kid"]
	if !ok {
		return nil, ErrNoKeyID
	}

	// Parse the kid
	var keyID ulid.ULID
	if keyID, err = ulid.Parse(kid.(string)); err != nil {
		return nil, fmt.Errorf("could not parse kid: %w", err)
	}

	if keyID.IsZero() {
		return nil, ErrInvalidKeyID
	}

	// Fetch the key from the list of managed keys
	keys := s.keys.Key(keyID.String())
	if len(keys) == 0 {
		return nil, ErrUnknownSigningKey
	}

	// If we have multiple keys, return the first one; this should not happen
	if len(keys) > 1 {
		log.Warn().Str("keyID", keyID.String()).
			Msg("multiple signing keys found for kid")
	}

	return keys[0].Key, nil
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
			if !errors.Is(err, ErrNotModified) {
				// If the error is not a 304 Not Modified, return it
				return fmt.Errorf("could not fetch OpenID configuration: %w", err)
			}
		}

		// Update the local configuration from the fetched configuration
		if s.config != nil {
			s.jwksURL = s.config.JWKSURI
		}
	}

	// Fetch the JWKS from Quarterdeck
	if expires, ok := s.expires[s.jwksURL]; !ok || now.After(expires) {
		if s.keys, err = s.JWKS(ctx); err != nil {
			if !errors.Is(err, ErrNotModified) {
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
		return nil, ErrMissingConfigURL
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
		return nil, ErrMissingJWKSURL
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
