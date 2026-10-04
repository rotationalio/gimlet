package quarterdeck_test

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/confire"
	"go.rtnl.ai/gimlet/auth"
	"go.rtnl.ai/gimlet/auth/authtest"
	"go.rtnl.ai/gimlet/auth/quarterdeck"
	"go.rtnl.ai/ulid"
)

func TestQuarterdeck(t *testing.T) {
	srv := authtest.New(t)
	client := srv.Client()

	qd, err := quarterdeck.New(srv.ConfigURL(), authtest.Audience,
		quarterdeck.WithClient(client),
		quarterdeck.WithIssuer(authtest.Issuer),
		quarterdeck.WithSigningMethods([]string{authtest.SigningMethod().Alg()}),
	)
	require.NoError(t, err, "could not create Quarterdeck instance")

	claims := &auth.Claims{
		Name:  "John Doe",
		Email: "jdoe@example.com",
	}
	claims.SetSubjectID(auth.SubjectUser, ulid.Make())

	accessToken, err := srv.CreateAccessToken(claims)
	require.NoError(t, err, "could not create access token")

	verified, err := qd.Verify(accessToken)
	require.NoError(t, err, "could not verify access token")
	require.NotNil(t, verified, "verified claims should not be nil")
	require.Equal(t, claims.Name, verified.Name, "name should match")
	require.Equal(t, claims.Email, verified.Email, "email should match")

	refreshToken, err := srv.CreateRefreshToken(claims)
	require.NoError(t, err, "could not create refresh token")

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

	refreshed, err := qd.Refresh(auth.Tokens{
		Context:      c,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})

	require.NoError(t, err, "could not refresh authentication")
	require.NotNil(t, refreshed, "refreshed tokens should not be nil")
	require.NotNil(t, refreshed.Claims, "refreshed claims should not be nil")
	require.NotZero(t, refreshed.AccessToken, "new access token should not be empty")
	require.NotZero(t, refreshed.RefreshToken, "new refresh token should not be empty")
	require.Equal(t, claims.Name, refreshed.Claims.Name, "new name should match old one")
	require.Equal(t, claims.Email, refreshed.Claims.Email, "new email should match old one")

	newVerified, err := qd.Verify(refreshed.AccessToken)
	require.NoError(t, err, "could not verify new access token")
	require.NotNil(t, newVerified, "new verified claims should not be nil")
	require.Equal(t, refreshed.Claims.Name, newVerified.Name, "name should match")
	require.Equal(t, refreshed.Claims.Email, newVerified.Email, "email should match")

	// Should manage 304 not modified responses
	err = qd.Sync()
	require.NoError(t, err, "could not synchronize Quarterdeck")
}

// Ensures every sync config field can be set from the environment.
func TestQuarterdeckSyncConfigFromEnvironment(t *testing.T) {
	env := map[string]string{
		"QUARTERDECK_SYNC_TIMEOUT":                 "31s",
		"QUARTERDECK_BACKOFF_TIMEOUT":              "6m",
		"QUARTERDECK_BACKOFF_INITIAL_INTERVAL":     "7s",
		"QUARTERDECK_BACKOFF_RANDOMIZATION_FACTOR": "0.25",
		"QUARTERDECK_BACKOFF_MULTIPLIER":           "3.5",
		"QUARTERDECK_BACKOFF_MAX_INTERVAL":         "90s",
		"QUARTERDECK_SYNC_INTERVAL":                "2h",
		"QUARTERDECK_MIN_SYNC_INTERVAL":            "45s",
		"QUARTERDECK_REAUTH_TIMEOUT":               "11s",
	}
	for key, value := range env {
		t.Setenv(key, value)
	}

	var config quarterdeck.SyncConfig
	err := confire.Process("quarterdeck", &config)
	require.NoError(t, err)
	require.Equal(t, quarterdeck.SyncConfig{
		SyncTimeout:                31 * time.Second,
		BackoffTimeout:             6 * time.Minute,
		BackoffInitialInterval:     7 * time.Second,
		BackoffRandomizationFactor: 0.25,
		BackoffMultiplier:          3.5,
		BackoffMaxInterval:         90 * time.Second,
		SyncInterval:               2 * time.Hour,
		MinSyncInterval:            45 * time.Second,
		ReauthTimeout:              11 * time.Second,
	}, config)

	_, err = quarterdeck.New(
		"https://quarterdeck.example/.well-known/openid-configuration",
		authtest.Audience,
		quarterdeck.NoSync(),
		quarterdeck.NoRun(),
		quarterdeck.WithSyncConfig(config),
	)
	require.NoError(t, err, "New should accept and apply the environment-loaded configuration")
}

// Ensures that validation checks for every field in the sync config are enforced.
func TestQuarterdeckSyncConfigValidation(t *testing.T) {
	tests := []struct {
		name  string
		field string
		set   func(*quarterdeck.SyncConfig)
	}{
		{
			name:  "sync timeout must be positive",
			field: "syncTimeout",
			set:   func(c *quarterdeck.SyncConfig) { c.SyncTimeout = 0 },
		},
		{
			name:  "backoff timeout must be positive",
			field: "backoffTimeout",
			set:   func(c *quarterdeck.SyncConfig) { c.BackoffTimeout = 0 },
		},
		{
			name:  "initial backoff interval must be positive",
			field: "backoffInitialInterval",
			set:   func(c *quarterdeck.SyncConfig) { c.BackoffInitialInterval = 0 },
		},
		{
			name:  "randomization factor must not be negative",
			field: "backoffRandomizationFactor",
			set:   func(c *quarterdeck.SyncConfig) { c.BackoffRandomizationFactor = -0.1 },
		},
		{
			name:  "randomization factor must be less than one",
			field: "backoffRandomizationFactor",
			set:   func(c *quarterdeck.SyncConfig) { c.BackoffRandomizationFactor = 1 },
		},
		{
			name:  "randomization factor cannot be NaN",
			field: "backoffRandomizationFactor",
			set:   func(c *quarterdeck.SyncConfig) { c.BackoffRandomizationFactor = math.NaN() },
		},
		{
			name:  "multiplier must be greater than one",
			field: "backoffMultiplier",
			set:   func(c *quarterdeck.SyncConfig) { c.BackoffMultiplier = 1 },
		},
		{
			name:  "multiplier cannot be NaN",
			field: "backoffMultiplier",
			set:   func(c *quarterdeck.SyncConfig) { c.BackoffMultiplier = math.NaN() },
		},
		{
			name:  "maximum backoff must not be below initial interval",
			field: "backoffMaxInterval",
			set:   func(c *quarterdeck.SyncConfig) { c.BackoffMaxInterval = time.Second },
		},
		{
			name:  "sync interval must be positive",
			field: "syncInterval",
			set:   func(c *quarterdeck.SyncConfig) { c.SyncInterval = 0 },
		},
		{
			name:  "minimum sync interval must be positive",
			field: "minSyncInterval",
			set:   func(c *quarterdeck.SyncConfig) { c.MinSyncInterval = 0 },
		},
		{
			name:  "reauth timeout must be positive",
			field: "reauthTimeout",
			set:   func(c *quarterdeck.SyncConfig) { c.ReauthTimeout = 0 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := quarterdeck.NewDefaultSyncConfig()
			require.NoError(t, err)
			tt.set(&config)
			require.ErrorContains(t, config.Validate(), tt.field)
		})
	}
}

func TestQuarterdeckSyncRateLimited(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)

	qd, err := quarterdeck.New(
		server.URL,
		authtest.Audience,
		quarterdeck.NoSync(),
		quarterdeck.NoRun(),
	)
	require.NoError(t, err)

	err = qd.Sync()
	require.ErrorIs(t, err, auth.ErrRateLimited, "expected rate-limit error, got %v", err)
	require.Equal(t, int32(1), requests.Load(), "429 response should not be retried")
}

// Ensures the run loop respects the configured minimum sync interval, no matter
// what the result of the sync attempt is.
func TestRunMinimumIntervalPreventsTightRetryLoop(t *testing.T) {
	// Each case starts with a valid discovery document and an already-expired JWKS
	// cache entry, then makes the next JWKS request return a different outcome. This
	// exercises the scheduling path after both successful and failed sync attempts.
	tests := []struct {
		name         string
		jwksStatus   int
		transportErr bool
	}{
		{name: "success with expired cache", jwksStatus: http.StatusOK},
		{name: "not modified", jwksStatus: http.StatusNotModified},
		{name: "rate limited", jwksStatus: http.StatusTooManyRequests},
		{name: "server error", jwksStatus: http.StatusInternalServerError},
		{name: "transport error", transportErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				configURL = "https://quarterdeck.example/.well-known/openid-configuration"
				jwksPath  = "/.well-known/jwks.json"
			)
			var jwksRequests atomic.Int32

			client := &http.Client{Transport: qdRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set("Content-Type", "application/json")

				// Keep discovery fresh so only JWKS expiry controls the next sync wait.
				if req.URL.Path == "/.well-known/openid-configuration" {
					header.Set("Cache-Control", "public, max-age=3600")
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     header,
						Body:       io.NopCloser(strings.NewReader(`{"issuer":"https://quarterdeck.example","authorization_endpoint":"https://quarterdeck.example/login","token_endpoint":"https://quarterdeck.example/token","jwks_uri":"https://quarterdeck.example` + jwksPath + `"}`)),
						Request:    req,
					}, nil
				}

				if req.URL.Path != jwksPath {
					return nil, errors.New("unexpected request path")
				}

				requestNumber := jwksRequests.Add(1)
				if requestNumber == 1 {
					// Seed a valid JWKS response that expires immediately. The next request
					// will exercise the response/error configured by this test case.
					header.Set("Cache-Control", "public, max-age=0")
					header.Set("ETag", `"test-etag"`)
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     header,
						Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
						Request:    req,
					}, nil
				}

				if tt.transportErr {
					return nil, errors.New("upstream unavailable")
				}
				if tt.jwksStatus == http.StatusNotModified || tt.jwksStatus == http.StatusOK {
					header.Set("Cache-Control", "public, max-age=0")
					header.Set("ETag", `"test-etag"`)
				}
				body := ""
				if tt.jwksStatus == http.StatusOK {
					body = `{"keys":[]}`
				}
				return &http.Response{
					StatusCode: tt.jwksStatus,
					Header:     header,
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    req,
				}, nil
			})}

			config, err := quarterdeck.NewDefaultSyncConfig()
			require.NoError(t, err)

			// Make the fallback interval effectively immediate, while setting a long
			// minimum wait. If Run ignores the minimum, the expired cache causes a
			// retry during the short observation window below.
			config.SyncInterval = time.Nanosecond
			config.MinSyncInterval = 24 * time.Hour

			// Keep retry attempts short so error cases finish quickly; jitter is
			// disabled for deterministic test timing.
			config.BackoffTimeout = 5 * time.Millisecond
			config.BackoffInitialInterval = time.Millisecond
			config.BackoffRandomizationFactor = 0
			config.BackoffMaxInterval = time.Millisecond

			qd, err := quarterdeck.New(
				configURL,
				authtest.Audience,
				quarterdeck.NoSync(),
				quarterdeck.NoRun(),
				quarterdeck.WithClient(client),
				quarterdeck.WithSyncConfig(config),
			)
			require.NoError(t, err)
			require.NoError(t, qd.Sync(), "initial sync should populate the expired JWKS cache")

			// A second sync reaches the case-specific JWKS response (or transport
			// error) after the cache has expired.
			err = qd.Sync()
			if tt.transportErr || tt.jwksStatus == http.StatusTooManyRequests || tt.jwksStatus >= 500 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// Run schedules asynchronously. Wait briefly—far less than the configured
			// 24-hour minimum—and ensure it did not immediately request expired JWKS.
			requestsBeforeRun := jwksRequests.Load()
			qd.Run()
			time.Sleep(25 * time.Millisecond)
			require.Equal(t, requestsBeforeRun, jwksRequests.Load(), "Run must not immediately retry against an expired cache, regardless of the sync response")
		})
	}
}

// Ensures that a 304 response refreshes the JWKS cache expiration metadata
// properly.
func TestDoNotModifiedRefreshesExpiration(t *testing.T) {
	const jwksURL = "https://quarterdeck.example/.well-known/jwks.json"
	var calls int

	// The first response seeds an expired ETag cache entry; the second returns a
	// 304 with fresh cache metadata. This isolates the conditional-request behavior.
	client := &http.Client{Transport: qdRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		header := make(http.Header)
		status := http.StatusOK
		if calls == 1 {
			// Force the next request to revalidate this cached response.
			header.Set("Cache-Control", "public, max-age=0")
			header.Set("ETag", `"test-etag"`)
		} else {
			// A 304 has no new body, but its headers should extend the cache expiry.
			header.Set("Cache-Control", "public, max-age=3600")
			header.Set("ETag", `"test-etag"`)
			status = http.StatusNotModified
			require.Equal(t, "test-etag", req.Header.Get("If-None-Match"))
		}
		return &http.Response{
			StatusCode: status,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})}

	qd, err := quarterdeck.New(
		jwksURL,
		authtest.Audience,
		quarterdeck.NoSync(),
		quarterdeck.NoRun(),
		quarterdeck.WithClient(client),
	)
	require.NoError(t, err)

	req, err := qd.NewRequest(context.Background(), http.MethodGet, jwksURL, nil)
	require.NoError(t, err)
	_, err = qd.Do(req, nil)
	require.NoError(t, err)

	// Verify the first response actually left an expired entry to revalidate.
	expires, ok := qd.Expires(jwksURL)
	require.True(t, ok)
	require.False(t, time.Now().Before(expires), "first response should expire immediately")

	// The second request should be conditional, return the not-modified sentinel,
	// and still refresh the cached expiry using the response headers.
	req, err = qd.NewRequest(context.Background(), http.MethodGet, jwksURL, nil)
	require.NoError(t, err)
	_, err = qd.Do(req, nil)
	require.ErrorIs(t, err, auth.ErrNotModified)
	require.Equal(t, 2, calls)

	expires, ok = qd.Expires(jwksURL)
	require.True(t, ok)
	require.True(t, expires.After(time.Now().Add(30*time.Minute)), "304 response should refresh the expired cache deadline")
}

type qdRoundTripFunc func(*http.Request) (*http.Response, error)

func (f qdRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
