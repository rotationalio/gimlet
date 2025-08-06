/*
Package authtest provides helper functionality for testing authentication with
Quarterdeck as simply as possible. This package focuses primarily on the issuance and
verification of JWT tokens rather than on providing mocking behavior the whole API.
*/
package authtest

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/auth"
	"go.rtnl.ai/ulid"
	"go.rtnl.ai/x/httpcc"
)

const (
	Audience    = "http://127.0.0.1"
	Issuer      = "http://127.0.0.1"
	ContentType = "application/json; charset=utf-8"
)

var (
	KeyID         = ulid.MustParse("01K20FY28DVXH9GPZ0S11D0JCA").String()
	signingMethod = jwt.SigningMethodEdDSA
)

// Server implements an endpoint to host JWKS public keys and also provides simple
// functionality to create access and refresh tokens that would be authenticated. This
// is run using an httptest.Server instance to make it easy to use in tests.
type Server struct {
	srv  *httptest.Server
	mux  *http.ServeMux
	url  *url.URL
	key  crypto.PrivateKey
	jwks *jose.JSONWebKeySet
	etag string
	nbf  time.Time
}

// Create and run a new auth test server. The returned server instance will be
// automatically closed when the test is complete using t.Cleanup.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/.well-known/jwks.json", s.CacheControl(s.JWKS))
	s.mux.HandleFunc("/.well-known/openid-configuration", s.CacheControl(s.OpenIDConfig))

	s.srv = httptest.NewServer(s.mux)
	t.Cleanup(s.srv.Close)

	var (
		pubkey crypto.PublicKey
		err    error
	)

	s.url, _ = url.Parse(s.srv.URL)
	pubkey, s.key, err = ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "could not generate ed25519 key pair")

	s.jwks = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       pubkey,
				Use:       "sig",
				KeyID:     KeyID,
				Algorithm: signingMethod.Alg(),
			},
		},
	}

	s.nbf = time.Now().In(time.UTC)
	return s
}

func (s *Server) URL() *url.URL {
	return s.url
}

func (s *Server) Client() *http.Client {
	return s.srv.Client()
}

func (s *Server) ConfigURL() string {
	if s.url == nil {
		return ""
	}
	uri := s.url.ResolveReference(&url.URL{Path: "/.well-known/openid-configuration"})
	return uri.String()
}

func (s *Server) CacheControl(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if the request has cache control headers and handle them accordingly.
		cc, err := httpcc.Request(r)
		if err != nil {
			http.Error(w, "could not parse cache control headers: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if inm, ok := cc.IfNoneMatch(); ok && inm == s.ETag() {
			w.Header().Set("ETag", s.ETag())
			http.Error(w, "etag match", http.StatusNotModified)
			return
		}

		if ims, ok := cc.IfModifiedSince(); ok && (ims.After(s.nbf) || ims.Equal(s.nbf)) {
			w.Header().Set("Last-Modified", s.nbf.Format(http.TimeFormat))
			http.Error(w, "not modified", http.StatusNotModified)
			return
		}

		// Add the ETag, Expires, and Cache-Control headers to the response.
		w.Header().Set("ETag", s.ETag())
		w.Header().Set("Expires", s.nbf.Add(10*time.Minute).Format(http.TimeFormat))
		w.Header().Set("Cache-Control", "public, max-age=600, immutable")

		// Call the next handler in the chain.
		next(w, r)
	}
}

// Returns the JWKS public keys for verifying tokens.
func (s *Server) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(s.jwks)
}

// Returns the openid-configuration for OIDC discovery.
func (s *Server) OpenIDConfig(w http.ResponseWriter, r *http.Request) {
	out := map[string]interface{}{
		"issuer":                                Issuer,
		"jwks_uri":                              s.srv.URL + "/.well-known/jwks.json",
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"token", "id_token"},
		"id_token_signing_alg_values_supported": []string{"RS256", "EdDSA"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email"},
	}

	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(out)
}

// Computes the Etag for the JWKS public keys.
func (s *Server) ETag() string {
	if s.etag == "" {
		hash := sha256.New()
		if err := json.NewEncoder(hash).Encode(s.jwks); err != nil {
			panic(err)
		}
		s.etag = hex.EncodeToString(hash.Sum(nil))
	}
	return s.etag
}

// CreateToken creates a token without overwriting the claims, which is useful for
// creating tokens with specific not before and expiration times for testing purposes.
func (s *Server) CreateToken(claims *auth.Claims) (string, error) {
	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = KeyID
	return token.SignedString(s.key)
}

// CreateAccessToken creates a new access token with the specified claims ensuring that
// the subject and timestmamps are set correctly. This is useful for quickly generating
// access tokens for testing purposes.
func (s *Server) CreateAccessToken(claims *auth.Claims) (string, error) {
	now := time.Now().In(time.UTC)
	sub := claims.RegisteredClaims.Subject

	claims.RegisteredClaims = jwt.RegisteredClaims{
		ID:        ulid.MakeSecure().String(),
		Subject:   sub,
		Audience:  jwt.ClaimStrings{Audience},
		Issuer:    Issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
	}

	return s.CreateToken(claims)
}

func (s *Server) Verify(tks string) (claims *auth.Claims, err error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{signingMethod.Alg()}),
		jwt.WithAudience(Audience),
		jwt.WithIssuer(Issuer),
	}

	var token *jwt.Token
	if token, err = jwt.ParseWithClaims(tks, &auth.Claims{}, s.GetKey, opts...); err != nil {
		return nil, err
	}

	var ok bool
	if claims, ok = token.Claims.(*auth.Claims); ok && token.Valid {
		// TODO: add claims specific validation here if needed.
		return claims, nil
	}

	// I haven't figured out a test that will allow us to reach this case; if you pass
	// in a token with a different type of claims, it will return an empty auth.Claims.
	return nil, auth.ErrUnparsableClaims
}

// GetKey is an jwt.KeyFunc that selects the public key from the list of managed
// internal keys based on the kid in the token header. If the kid does not exist an
// error is returned and the token will not be able to be verified.
func (s *Server) GetKey(token *jwt.Token) (key interface{}, err error) {
	// Per JWT security notice: do not forget to validate alg is expected
	if token.Method.Alg() != signingMethod.Alg() {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
	}

	// Fetch the kid from the header
	kid, ok := token.Header["kid"]
	if !ok {
		return nil, auth.ErrNoKeyID
	}

	// Fetch the key from the list of managed keys
	keys := s.jwks.Key(kid.(string))
	if len(keys) == 0 {
		return nil, auth.ErrUnknownSigningKey
	}

	// If we have multiple keys, return the first one; this should not happen
	if len(keys) > 1 {
		log.Warn().Str("keyID", kid.(string)).
			Msg("multiple signing keys found for kid")
	}

	return keys[0].Key, nil
}

func SigningMethod() jwt.SigningMethod {
	return signingMethod
}
