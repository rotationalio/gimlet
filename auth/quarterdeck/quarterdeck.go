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
	"go.rtnl.ai/x/backoff"
)

const (
	// Default timeout for synchronization requests to Quarterdeck.
	SyncTimeout = 20 * time.Second

	// Default timeout for backoff retries when synchronizing with Quarterdeck.
	BackoffTimeout = 5 * time.Minute

	// Default interval for synchronization of JWKS and OpenID configuration if not
	// specified by the Expires header.
	SyncInterval = 1 * time.Hour

	// Default timeout for reauthentication requests to Quarterdeck.
	ReauthTimeout = 5 * time.Second
)

var (
	ErrNoLoginURL     = errors.New("no login URL specified or authentication endpoint set in OIDC discovery data")
	ErrNoReauthURL    = errors.New("no reauthentication URL specified or reauthentication endpoint set in OIDC discovery data")
	ErrNoAccessToken  = errors.New("no access token provided in response")
	ErrNoRefreshToken = errors.New("no refresh token provided in response")
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
	loginURL       *ConfigURL
	reauthURL      *ConfigURL
	syncInit       bool
	runInit        bool

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
		loginURL:  &ConfigURL{},
		reauthURL: &ConfigURL{},
		etag:      make(map[string]string),
		expires:   make(map[string]time.Time),
		syncInit:  true,
		runInit:   true,
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
	if qd.syncInit {
		if err = qd.Sync(); err != nil {
			return nil, err
		}
	}

	// Start the synchronization process in a goroutine
	if qd.runInit {
		qd.Run()
	}

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

// Implements the Reauthenticator interface to reauthenticate the user if the
// access token is expired and a refresh token is available.
func (s *Quarterdeck) Refresh(accessToken, refreshToken string) (claims *auth.Claims, newAccessToken, newRefreshToken string, err error) {
	s.RLock()
	defer s.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), ReauthTimeout)
	defer cancel()

	if newAccessToken, newRefreshToken, err = s.Reauthenticate(ctx, accessToken, refreshToken); err != nil {
		return nil, "", "", err
	}

	var token *jwt.Token
	if token, err = s.parser.ParseWithClaims(newAccessToken, &auth.Claims{}, s.GetKey); err != nil {
		return nil, "", "", err
	}

	var ok bool
	if claims, ok = token.Claims.(*auth.Claims); ok && token.Valid {
		return claims, newAccessToken, newRefreshToken, nil
	}

	// I haven't figured out a test that will allow us to reach this case; if you pass
	// in a token with a different type of claims, it will return an empty auth.Claims.
	return nil, "", "", auth.ErrUnparsableClaims
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

	// If no keys have been synced from the server return an error
	if s.keys == nil {
		return nil, auth.ErrUnsynced
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
		if err := s.Sync(); err != nil {
			log.Error().Err(err).Msg("could not synchronize keys with Quarterdeck")
		}
		s.Run() // Restart the synchronization process
	})
}

// Synchronizes the JWKS and OpenID configuration from Quarterdeck, respecting the
// cache-control headers and ETag for caching purposes.
func (s *Quarterdeck) Sync() (err error) {
	// Maximum time limit to allow synchronization to complete
	ctx, cancel := context.WithTimeout(context.Background(), BackoffTimeout)
	defer cancel()

	// Use exponential backoff to retry synchronization in case of errors
	if _, err = backoff.Retry(ctx, s.sync, backoff.WithNotify(notify("could not synchronize with Quarterdeck"))); err != nil {
		return err
	}
	return nil
}

func (s *Quarterdeck) sync() (_ bool, err error) {
	s.Lock()
	defer s.Unlock()

	now := time.Now()
	updated := false

	ctx, cancel := context.WithTimeout(context.Background(), SyncTimeout)
	defer cancel()

	// Fetch the OpenID configuration from Quarterdeck
	if expires, ok := s.expires[s.configURL]; !ok || now.After(expires) {
		var config *OpenIDConfiguration
		if config, err = s.Config(ctx); err != nil {
			if !errors.Is(err, auth.ErrNotModified) {
				// If the error is not a 304 Not Modified, return it
				return updated, fmt.Errorf("could not fetch OpenID configuration: %w", err)
			}
		}

		// Only replace the local configuration if we fetched a new one
		if config != nil {
			s.config = config
			updated = true
		}

		// Update the local configuration from the fetched configuration
		if s.config != nil {
			// Always update the JWKS URL if it changed
			if s.jwksURL != s.config.JWKSURI {
				delete(s.expires, s.jwksURL)
				s.jwksURL = s.config.JWKSURI
			}

			// Update the issuer if it isn't set
			if s.issuer == "" {
				s.issuer = s.config.Issuer
			}

			// If the user did not specify a login URL, use the one from the configuration
			s.loginURL.Update(s.config.AuthorizationEP)

			// If the user did not specify a reauth URL, use the one from the configuration
			s.reauthURL.Update(s.config.TokenEP)
		}
	}

	// Fetch the JWKS from Quarterdeck
	if expires, ok := s.expires[s.jwksURL]; !ok || now.After(expires) {
		var keys *jose.JSONWebKeySet
		if keys, err = s.JWKS(ctx); err != nil {
			if !errors.Is(err, auth.ErrNotModified) {
				// If the error is not a 304 Not Modified, return it
				return updated, fmt.Errorf("could not fetch JWKS: %w", err)
			}
		}

		// Only replace the local keys if we fetched new ones
		if keys != nil {
			s.keys = keys
			updated = true
		}
	}

	// Create the JWT parser if there were updates
	if updated {
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
	}

	return updated, nil
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
	if req, err = s.NewRequest(ctx, http.MethodGet, s.configURL, nil); err != nil {
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
	if req, err = s.NewRequest(ctx, http.MethodGet, s.jwksURL, nil); err != nil {
		return nil, err
	}

	if _, err = s.Do(req, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// Reauthenticates and returns new access token by performing a POST request to
// Quarterdeck.
func (s *Quarterdeck) Reauthenticate(ctx context.Context, accessToken, refreshToken string) (newAccessToken, newRefreshToken string, err error) {
	var (
		reauthURL string
		req       *http.Request
		out       *TokenRequest
		in        *TokenReply
	)

	if reauthURL = s.reauthURL.String(); reauthURL == "" {
		return "", "", ErrNoReauthURL
	}

	out = &TokenRequest{RefreshToken: refreshToken}
	if req, err = s.NewRequest(ctx, http.MethodPost, reauthURL, out); err != nil {
		return "", "", errors.Join(err, errors.New("could not create new quarterdeck request"))
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	in = &TokenReply{}
	if _, err = s.Do(req, in); err != nil {
		return "", "", err
	}

	if err = in.Validate(); err != nil {
		return "", "", err
	}

	return in.AccessToken, in.RefreshToken, nil
}

func notify(msg string) backoff.Notify {
	return func(err error, delay time.Duration) {
		log.Warn().Err(err).Dur("delay", delay).Msg(msg)
	}
}
