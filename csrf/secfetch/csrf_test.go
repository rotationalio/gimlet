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
	secfetch "go.rtnl.ai/gimlet/csrf/secfetch"
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
				headers.Set("Origin", test.origin)
			}
			recorder := serve(t, http.MethodPost, headers, secfetch.WithExpectedOrigins(approvedOrigins))
			if test.allowed {
				require.Equal(t, http.StatusNoContent, recorder.Code)
				return
			}
			assertCSRFRejected(t, recorder, secfetch.ErrorHeader)
		})
	}
}

// Confirms safe methods bypass Fetch Metadata checks while writes reject cross-site requests.
func TestSafeAndMutatingMethods(t *testing.T) {
	t.Run("safe methods bypass metadata checks", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
			t.Run(method, func(t *testing.T) {
				headers := http.Header{"Sec-Fetch-Site": []string{"cross-site"}}
				recorder := serve(t, method, headers)
				require.Equal(t, http.StatusNoContent, recorder.Code)
			})
		}
	})

	t.Run("mutating methods reject cross-site requests", func(t *testing.T) {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			t.Run(method, func(t *testing.T) {
				headers := http.Header{"Sec-Fetch-Site": []string{"cross-site"}}
				recorder := serve(t, method, headers)
				assertCSRFRejected(t, recorder, secfetch.ErrorHeader)
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
			recorder := serve(t, test.method, http.Header{"Sec-Fetch-Site": []string{"cross-site"}}, secfetch.WithSafeHTTPMethods(test.safe))
			if test.allowed {
				require.Equal(t, http.StatusNoContent, recorder.Code)
				return
			}
			assertCSRFRejected(t, recorder, secfetch.ErrorHeader)
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
		"Sec-Fetch-Site": []string{"cross-site"},
		"Sec-Fetch-Mode": []string{"cors"},
		"Sec-Fetch-Dest": []string{"empty"},
		"Referer":        []string{"https://app.example.com/private?token=secret"},
	}
	recorder := serve(t, http.MethodPost, headers, secfetch.WithLogOnly(true))
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Empty(t, recorder.Header().Get(secfetch.ErrorHeader))
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
	headers := http.Header{"Sec-Fetch-Site": []string{"same-origin", "cross-site"}}
	recorder := serve(t, http.MethodPost, headers)
	assertCSRFRejected(t, recorder, secfetch.ErrorHeader)
}

// Builds a small Gin route and sends one request through the middleware under test.
func serve(t *testing.T, method string, headers http.Header, options ...secfetch.Option) *httptest.ResponseRecorder {
	t.Helper()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, "/action", secfetch.Middleware(options...), func(c *gin.Context) {
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
	require.Equal(t, secfetch.ErrorRequestRejected, recorder.Header().Get(errorHeader))
	require.Contains(t, strings.ToLower(recorder.Body.String()), "csrf verification failed for request")
}
