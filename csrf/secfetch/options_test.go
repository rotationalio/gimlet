package csrf_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	secfetch "go.rtnl.ai/gimlet/csrf/secfetch"
)

// Ensures the custom bypass applies only when Fetch-Site, Origin, and Referer are absent.
func TestFallbackRunsOnlyWithoutRequestMetadata(t *testing.T) {
	calls := 0
	fallback := secfetch.WithFallback(func(*gin.Context) bool {
		calls++
		return true
	})

	recorder := serve(t, http.MethodPost, make(http.Header), fallback)
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, 1, calls)

	for _, headers := range []http.Header{
		{"Sec-Fetch-Site": []string{"future-value"}},
		{"Sec-Fetch-Site": []string{"cross-site"}},
		{"Origin": []string{"https://untrusted.example"}},
		{"Referer": []string{"https://untrusted.example/action"}},
	} {
		recorder := serve(t, http.MethodPost, headers, fallback)
		assertCSRFRejected(t, recorder, secfetch.ErrorHeader)
	}
	require.Equal(t, 1, calls, "requests with any provenance header must not invoke the fallback")
}

// Confirms the explicitly relaxed policy can permit state-changing requests from site none.
func TestSiteNoneCanBeExplicitlyAllowed(t *testing.T) {
	headers := http.Header{"Sec-Fetch-Site": []string{"none"}}
	recorder := serve(t, http.MethodPost, headers, secfetch.WithAllowSiteNone(true))
	require.Equal(t, http.StatusNoContent, recorder.Code)
}

// Exercises optional mode and destination allowlists and required-header settings.
func TestFetchModeAndDestinationOptions(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		options []secfetch.Option
		allowed bool
	}{
		{
			name:    "unconfigured headers are optional",
			headers: http.Header{"Sec-Fetch-Site": []string{"same-origin"}},
			allowed: true,
		},
		{
			name: "allowed mode and destination",
			headers: http.Header{
				"Sec-Fetch-Site": []string{"same-origin"},
				"Sec-Fetch-Mode": []string{"cors"},
				"Sec-Fetch-Dest": []string{"empty"},
			},
			options: []secfetch.Option{
				secfetch.WithAllowedFetchModes([]string{"cors", "same-origin"}),
				secfetch.WithAllowedFetchDestinations([]string{"empty"}),
			},
			allowed: true,
		},
		{
			name: "disallowed mode",
			headers: http.Header{
				"Sec-Fetch-Site": []string{"same-origin"},
				"Sec-Fetch-Mode": []string{"navigate"},
			},
			options: []secfetch.Option{secfetch.WithAllowedFetchModes([]string{"cors"})},
			allowed: false,
		},
		{
			name:    "required mode missing",
			headers: http.Header{"Sec-Fetch-Site": []string{"same-origin"}},
			options: []secfetch.Option{secfetch.WithRequireFetchMode(true)},
			allowed: false,
		},
		{
			name: "disallowed destination",
			headers: http.Header{
				"Sec-Fetch-Site": []string{"same-origin"},
				"Sec-Fetch-Dest": []string{"document"},
			},
			options: []secfetch.Option{secfetch.WithAllowedFetchDestinations([]string{"empty"})},
			allowed: false,
		},
		{
			name:    "required destination missing",
			headers: http.Header{"Sec-Fetch-Site": []string{"same-origin"}},
			options: []secfetch.Option{secfetch.WithRequireFetchDestination(true)},
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
			assertCSRFRejected(t, recorder, secfetch.ErrorHeader)
		})
	}
}

// Checks that a namespace produces a distinct response header without changing the signal.
func TestNamespacedErrorSignal(t *testing.T) {
	headers := http.Header{"Sec-Fetch-Site": []string{"cross-site"}}
	recorder := serve(t, http.MethodPost, headers, secfetch.WithNamespace(" Endeavor.Service "))
	assertCSRFRejected(t, recorder, "X-Endeavor_service-CSRF-Error")
	require.Empty(t, recorder.Header().Get(secfetch.ErrorHeader))
}
