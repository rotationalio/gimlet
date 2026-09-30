package csrf_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	csrf "go.rtnl.ai/gimlet/csrf/secfetch"
)

// Verifies missing and unknown site metadata use configured Origin and Referer fallback rules.
func TestMissingAndUnknownMetadataFallback(t *testing.T) {
	origins := []string{"https://app.example.com"}

	tests := []struct {
		name    string
		headers http.Header
		options []csrf.Option
		allowed bool
	}{
		{
			name:    "missing-site-with-approved-origin",
			headers: http.Header{csrf.HeaderOrigin: []string{"https://app.example.com"}},
			options: []csrf.Option{csrf.WithExpectedOrigins(origins)},
			allowed: true,
		},
		{
			name:    "missing-site-with-approved-referer-path-and-query",
			headers: http.Header{csrf.HeaderReferer: []string{"https://app.example.com/forms/edit?from=mail"}},
			options: []csrf.Option{csrf.WithExpectedOrigins(origins)},
			allowed: true,
		},
		{
			name:    "missing-site-default-deny",
			headers: make(http.Header),
			allowed: false,
		},
		{
			name:    "missing-site-explicitly-allowed",
			headers: make(http.Header),
			options: []csrf.Option{csrf.WithAllowMissingMetadata(true)},
			allowed: true,
		},
		{
			name: "untrusted-origin-does-not-fall-back-to-trusted-referer",
			headers: http.Header{
				csrf.HeaderOrigin:  []string{"https://attacker.example"},
				csrf.HeaderReferer: []string{"https://app.example.com/forms"},
			},
			options: []csrf.Option{csrf.WithExpectedOrigins(origins)},
			allowed: false,
		},
		{
			name:    "unknown-site-with-approved-origin",
			headers: http.Header{csrf.HeaderSecFetchSite: []string{"future-value"}, csrf.HeaderOrigin: []string{"https://app.example.com"}},
			options: []csrf.Option{csrf.WithExpectedOrigins(origins)},
			allowed: true,
		},
		{
			name:    "unknown-site-default-deny",
			headers: http.Header{csrf.HeaderSecFetchSite: []string{"future-value"}},
			allowed: false,
		},
		{
			name:    "unknown-site-explicitly-allowed",
			headers: http.Header{csrf.HeaderSecFetchSite: []string{"future-value"}},
			options: []csrf.Option{csrf.WithAllowUnknownSite(true)},
			allowed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := serve(t, http.MethodPost, test.headers, test.options...)
			if test.allowed {
				require.Equal(t, http.StatusNoContent, recorder.Code)
				return
			}
			assertCSRFRejected(t, recorder, csrf.HeaderError)
		})
	}
}

// Rejects mismatched Origin or Referer before missing/unknown-site options and fallback.
func TestUntrustedProvenanceCannotBeOverriddenForMissingOrUnknownSite(t *testing.T) {
	trustedOrigins := []string{"https://app.example.com"}
	tests := []struct {
		name    string
		headers http.Header
		option  csrf.Option
	}{
		{
			name:    "missing site with untrusted origin",
			headers: http.Header{csrf.HeaderOrigin: []string{"https://attacker.example"}},
			option:  csrf.WithAllowMissingMetadata(true),
		},
		{
			name:    "unknown site with untrusted origin",
			headers: http.Header{csrf.HeaderSecFetchSite: []string{"future-value"}, csrf.HeaderOrigin: []string{"https://attacker.example"}},
			option:  csrf.WithAllowUnknownSite(true),
		},
		{
			name:    "untrusted referer with missing site",
			headers: http.Header{csrf.HeaderReferer: []string{"https://attacker.example/action"}},
			option:  csrf.WithAllowMissingMetadata(true),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fallbackCalls := 0
			recorder := serve(t, http.MethodPost, test.headers,
				csrf.WithExpectedOrigins(trustedOrigins),
				test.option,
				csrf.WithFallback(func(*gin.Context) bool {
					fallbackCalls++
					return true
				}),
			)
			assertCSRFRejected(t, recorder, csrf.HeaderError)
			require.Equal(t, 0, fallbackCalls)
		})
	}
}

// Confirms origin matching includes scheme, hostname, and non-default port exactly.
func TestExpectedOriginsAreExact(t *testing.T) {
	tests := []struct {
		name       string
		expected   []string
		request    string
		wantStatus int
	}{
		{
			name:       "default https port is equivalent",
			expected:   []string{"https://app.example.com"},
			request:    "https://app.example.com:443",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "scheme must match",
			expected:   []string{"https://app.example.com"},
			request:    "http://app.example.com",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "port must match (success)",
			expected:   []string{"https://app.example.com:8443"},
			request:    "https://app.example.com:8443",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "port must match (forbidden)",
			expected:   []string{"https://app.example.com:8443"},
			request:    "https://app.example.com",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "hostname suffix is not trusted",
			expected:   []string{"https://example.com"},
			request:    "https://evil-example.com",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := http.Header{
				csrf.HeaderSecFetchSite: []string{"same-site"},
				csrf.HeaderOrigin:       []string{test.request},
			}
			recorder := serve(t, http.MethodPost, headers, csrf.WithExpectedOrigins(test.expected))
			require.Equal(t, test.wantStatus, recorder.Code)
		})
	}
}

// Rejects malformed origins and referers while accepting a valid IPv6 origin.
func TestMalformedOriginsAndIPv6(t *testing.T) {
	trustedOrigin := "https://app.example.com"
	tests := []struct {
		name     string
		origin   string
		referer  string
		expected []string
		allowed  bool
	}{
		{
			name:     "invalid origin syntax",
			origin:   "://bad",
			expected: []string{trustedOrigin},
		},
		{
			name:     "opaque origin",
			origin:   "https:opaque",
			expected: []string{trustedOrigin},
		},
		{
			name:     "origin with user info",
			origin:   "https://user@app.example.com",
			expected: []string{trustedOrigin},
		},
		{
			name:     "unsupported origin scheme",
			origin:   "ftp://app.example.com",
			expected: []string{trustedOrigin},
		},
		{
			name:     "origin without host",
			origin:   "https:///app.example.com",
			expected: []string{trustedOrigin},
		},
		{
			name:     "origin with path",
			origin:   "https://app.example.com/path",
			expected: []string{trustedOrigin},
		},
		{
			name:     "origin with invalid port",
			origin:   "https://app.example.com:70000",
			expected: []string{trustedOrigin},
		},
		{
			name:     "invalid referer syntax",
			referer:  "://bad",
			expected: []string{trustedOrigin},
		},
		{
			name:     "IPv6 origin",
			origin:   "https://[2001:db8::1]",
			expected: []string{"https://[2001:db8::1]"},
			allowed:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := make(http.Header)
			if test.origin != "" {
				headers.Set(csrf.HeaderSecFetchSite, "same-site")
				headers.Set(csrf.HeaderOrigin, test.origin)
			}
			if test.referer != "" {
				headers.Set(csrf.HeaderReferer, test.referer)
			}
			recorder := serve(t, http.MethodPost, headers, csrf.WithExpectedOrigins(test.expected))
			if test.allowed {
				require.Equal(t, http.StatusNoContent, recorder.Code)
				return
			}
			assertCSRFRejected(t, recorder, csrf.HeaderError)
		})
	}
}
