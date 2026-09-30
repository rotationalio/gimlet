package csrf_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	csrf "go.rtnl.ai/gimlet/csrf/secfetch"
)

// Ensures the custom bypass applies only when Fetch-Site, Origin, and Referer are absent.
func TestFallbackRunsOnlyWithoutRequestMetadata(t *testing.T) {
	calls := 0
	fallback := csrf.WithFallback(func(*gin.Context) bool {
		calls++
		return true
	})

	recorder := serve(t, http.MethodPost, make(http.Header), fallback)
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, 1, calls)

	for _, headers := range []http.Header{
		{csrf.HeaderSecFetchSite: []string{"future-value"}},
		{csrf.HeaderSecFetchSite: []string{"cross-site"}},
		{csrf.HeaderOrigin: []string{"https://untrusted.example"}},
		{csrf.HeaderReferer: []string{"https://untrusted.example/action"}},
	} {
		recorder := serve(t, http.MethodPost, headers, fallback)
		assertCSRFRejected(t, recorder, csrf.HeaderError)
	}
	require.Equal(t, 1, calls, "requests with any provenance header must not invoke the fallback")
}

// Confirms the explicitly relaxed policy can permit state-changing requests from site none.
func TestSiteNoneCanBeExplicitlyAllowed(t *testing.T) {
	headers := http.Header{csrf.HeaderSecFetchSite: []string{"none"}}
	recorder := serve(t, http.MethodPost, headers, csrf.WithAllowSiteNone(true))
	require.Equal(t, http.StatusNoContent, recorder.Code)
}

// Exercises optional mode and destination allowlists and required-header settings.
func TestFetchModeAndDestinationOptions(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		options []csrf.Option
		allowed bool
	}{
		{
			name:    "unconfigured headers are optional",
			headers: http.Header{csrf.HeaderSecFetchSite: []string{"same-origin"}},
			allowed: true,
		},
		{
			name: "allowed mode and destination",
			headers: http.Header{
				csrf.HeaderSecFetchSite: []string{"same-origin"},
				csrf.HeaderSecFetchMode: []string{"cors"},
				csrf.HeaderSecFetchDest: []string{"empty"},
			},
			options: []csrf.Option{
				csrf.WithAllowedFetchModes([]string{"cors", "same-origin"}),
				csrf.WithAllowedFetchDestinations([]string{"empty"}),
			},
			allowed: true,
		},
		{
			name: "disallowed mode",
			headers: http.Header{
				csrf.HeaderSecFetchSite: []string{"same-origin"},
				csrf.HeaderSecFetchMode: []string{"navigate"},
			},
			options: []csrf.Option{csrf.WithAllowedFetchModes([]string{"cors"})},
			allowed: false,
		},
		{
			name:    "required mode missing",
			headers: http.Header{csrf.HeaderSecFetchSite: []string{"same-origin"}},
			options: []csrf.Option{csrf.WithRequireFetchMode(true)},
			allowed: false,
		},
		{
			name: "disallowed destination",
			headers: http.Header{
				csrf.HeaderSecFetchSite: []string{"same-origin"},
				csrf.HeaderSecFetchDest: []string{"document"},
			},
			options: []csrf.Option{csrf.WithAllowedFetchDestinations([]string{"empty"})},
			allowed: false,
		},
		{
			name:    "required destination missing",
			headers: http.Header{csrf.HeaderSecFetchSite: []string{"same-origin"}},
			options: []csrf.Option{csrf.WithRequireFetchDestination(true)},
			allowed: false,
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

// Checks that a namespace produces a distinct response header without changing the signal.
func TestNamespacedErrorSignal(t *testing.T) {
	headers := http.Header{"Sec-Fetch-Site": []string{"cross-site"}}
	recorder := serve(t, http.MethodPost, headers, csrf.WithNamespace(" Endeavor.Service "))
	assertCSRFRejected(t, recorder, "X-Endeavor_service-CSRF-Error")
	require.Empty(t, recorder.Header().Get(csrf.HeaderError))
}
