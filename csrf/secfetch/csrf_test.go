package csrf_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	csrf "go.rtnl.ai/gimlet/csrf/secfetch"
	"go.rtnl.ai/x/rlog"
)

// Covers every defined Sec-Fetch-Site value and the unknown-value fallback policy.
func TestSecFetchSiteValues(t *testing.T) {
	approvedOrigins := []string{"https://app.example.com"}
	tests := []struct {
		name    string
		site    string
		origin  string
		allowed bool
	}{
		{
			name:    "same-origin",
			site:    "same-origin",
			allowed: true,
		},
		{
			name:    "same-origin-keeps-existing-site-policy",
			site:    "same-origin",
			origin:  "https://other.example.com",
			allowed: true,
		},
		{
			name:    "same-site-approved-origin",
			site:    "same-site",
			origin:  "https://app.example.com",
			allowed: true,
		},
		{
			name:    "same-site-unapproved-origin",
			site:    "same-site",
			origin:  "https://other.example.com",
			allowed: false,
		},
		{
			name:    "same-site-missing-origin",
			site:    "same-site",
			allowed: false,
		},
		{
			name:    "cross-site-even-with-approved-origin",
			site:    "cross-site",
			origin:  "https://app.example.com",
			allowed: false,
		},
		{
			name:    "none-default-deny",
			site:    "none",
			allowed: false,
		},
		{
			name:    "unknown-with-approved-origin-fallback",
			site:    "future-value",
			origin:  "https://app.example.com",
			allowed: true,
		},
		{
			name:    "unknown-default-deny",
			site:    "future-value",
			allowed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set("Sec-Fetch-Site", test.site)
			if test.origin != "" {
				headers.Set(csrf.HeaderOrigin, test.origin)
			}
			recorder := serve(t, http.MethodPost, headers, csrf.WithExpectedOrigins(approvedOrigins))
			if test.allowed {
				require.Equal(t, http.StatusNoContent, recorder.Code)
				return
			}
			assertCSRFRejected(t, recorder, csrf.HeaderError)
		})
	}
}

// Uses the fallback only when Fetch-Site, Origin, and Referer provide no evidence to compare.
func TestFallbackRequiresNoRequestMetadata(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		allowed        bool
		fallbackCalled bool
	}{
		{
			name:           "missing metadata uses fallback",
			allowed:        true,
			fallbackCalled: true,
		},
		{
			name:    "approved origin is checked before fallback",
			headers: http.Header{csrf.HeaderOrigin: []string{"https://app.example.com"}},
			allowed: true,
		},
		{
			name:    "unapproved origin cannot be overridden by fallback",
			headers: http.Header{csrf.HeaderOrigin: []string{"https://attacker.example"}},
		},
		{
			name:    "unapproved referer cannot be overridden by fallback",
			headers: http.Header{csrf.HeaderReferer: []string{"https://attacker.example/action"}},
		},
		{
			name:    "unknown site cannot be overridden by fallback",
			headers: http.Header{csrf.HeaderSecFetchSite: []string{"future-value"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fallbackCalls := 0
			recorder := serve(t, http.MethodPost, test.headers,
				csrf.WithExpectedOrigins([]string{"https://app.example.com"}),
				csrf.WithFallback(func(*gin.Context) bool {
					fallbackCalls++
					return true
				}),
			)

			require.Equal(t, test.fallbackCalled, fallbackCalls > 0)
			if test.allowed {
				require.Equal(t, http.StatusNoContent, recorder.Code)
				return
			}
			assertCSRFRejected(t, recorder, csrf.HeaderError)
		})
	}
}

// Rejects a request when the fallback runs and does not approve it.
func TestFallbackRejectsRequest(t *testing.T) {
	fallbackCalls := 0
	recorder := serve(t, http.MethodPost, make(http.Header),
		csrf.WithFallback(func(*gin.Context) bool {
			fallbackCalls++
			return false
		}),
	)

	require.Equal(t, 1, fallbackCalls)
	assertCSRFRejected(t, recorder, csrf.HeaderError)
}

// Confirms safe methods bypass Fetch Metadata checks while writes reject cross-site requests.
func TestSafeAndMutatingMethods(t *testing.T) {
	t.Run("safe methods bypass metadata checks", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
			t.Run(method, func(t *testing.T) {
				headers := http.Header{csrf.HeaderSecFetchSite: []string{"cross-site"}}
				recorder := serve(t, method, headers)
				require.Equal(t, http.StatusNoContent, recorder.Code)
			})
		}
	})

	t.Run("mutating methods reject cross-site requests", func(t *testing.T) {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			t.Run(method, func(t *testing.T) {
				headers := http.Header{csrf.HeaderSecFetchSite: []string{"cross-site"}}
				recorder := serve(t, method, headers)
				assertCSRFRejected(t, recorder, csrf.HeaderError)
			})
		}
	})
}

// Ensures the safe-method option can only narrow the fixed safe-method set.
func TestSafeHTTPMethodsOption(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		safe    []string
		allowed bool
	}{
		{
			name:    "configured get bypasses checks",
			method:  http.MethodGet,
			safe:    []string{"GET"},
			allowed: true,
		},
		{
			name:    "configured head bypasses checks",
			method:  http.MethodHead,
			safe:    []string{"HEAD"},
			allowed: true,
		},
		{
			name:    "configured options bypasses checks",
			method:  http.MethodOptions,
			safe:    []string{"OPTIONS"},
			allowed: true,
		},
		{
			name:    "omitted safe method is checked",
			method:  http.MethodHead,
			safe:    []string{"GET"},
			allowed: false,
		},
		{
			name: "unsafe method cannot be exempted", method: http.MethodPost,
			safe:    []string{"POST"},
			allowed: false,
		},
		{
			name:    "empty list checks even get",
			method:  http.MethodGet,
			safe:    []string{},
			allowed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := serve(t, test.method, http.Header{csrf.HeaderSecFetchSite: []string{"cross-site"}}, csrf.WithSafeHTTPMethods(test.safe))
			if test.allowed {
				require.Equal(t, http.StatusNoContent, recorder.Code)
				return
			}
			assertCSRFRejected(t, recorder, csrf.HeaderError)
		})
	}
}

// Records would-be rejections and lets the request reach its handler in log-only mode.
func TestLogOnlyMode(t *testing.T) {
	original := *rlog.Default()
	originalLevel := rlog.Level()
	var logs bytes.Buffer
	rlog.SetDefault(rlog.New(slog.New(slog.NewJSONHandler(&logs, nil))))
	rlog.SetLevel(slog.LevelDebug)
	t.Cleanup(func() {
		rlog.SetDefault(&original)
		rlog.SetLevel(originalLevel)
	})

	headers := http.Header{
		csrf.HeaderSecFetchSite: []string{"cross-site"},
		csrf.HeaderSecFetchMode: []string{"cors"},
		csrf.HeaderSecFetchDest: []string{"empty"},
		csrf.HeaderReferer:      []string{"https://app.example.com/private?token=secret"},
	}
	recorder := serve(t, http.MethodPost, headers,
		csrf.WithExpectedOrigins([]string{"https://app.example.com"}),
		csrf.WithLogOnly(true),
	)
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Empty(t, recorder.Header().Get(csrf.HeaderError))
	require.Contains(t, logs.String(), "CSRF request would be rejected")
	require.Contains(t, logs.String(), `"reason":"cross_site"`)
	require.Contains(t, logs.String(), `"method":"POST"`)
	require.Contains(t, logs.String(), `"sec_fetch_mode":"cors"`)
	require.Contains(t, logs.String(), `"sec_fetch_dest":"empty"`)
	require.Contains(t, logs.String(), `"referer_present":true`)
	require.Contains(t, logs.String(), `"referer_origin":"https://app.example.com"`)
	require.NotContains(t, logs.String(), "token=secret")
}

// Rejects duplicate Sec-Fetch-Site values instead of trusting an ambiguous value.
func TestDuplicateFetchMetadataHeaderRejected(t *testing.T) {
	headers := http.Header{csrf.HeaderSecFetchSite: []string{"same-origin", "cross-site"}}
	recorder := serve(t, http.MethodPost, headers)
	assertCSRFRejected(t, recorder, csrf.HeaderError)
}

// Builds a small Gin route and sends one request through the middleware under test.
func serve(t *testing.T, method string, headers http.Header, options ...csrf.Option) *httptest.ResponseRecorder {
	t.Helper()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, "/action", csrf.Middleware(options...), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(method, "https://app.example.com/action", nil)
	request.Header = headers.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("Accept", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

// Checks the forbidden response, stable error header, and standard error body.
func assertCSRFRejected(t *testing.T, recorder *httptest.ResponseRecorder, errorHeader string) {
	t.Helper()
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Equal(t, csrf.ErrorRequestRejected, recorder.Header().Get(errorHeader))
	require.Contains(t, strings.ToLower(recorder.Body.String()), "csrf verification failed for request")
}
