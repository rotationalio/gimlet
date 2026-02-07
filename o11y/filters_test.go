package o11y_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/o11y"
)

func TestFilters(t *testing.T) {
	t.Run("Routes", func(t *testing.T) {
		tests := []struct {
			method string
			target string
			assert require.BoolAssertionFunc
		}{
			{http.MethodGet, "/v1/status", require.False},
			{http.MethodGet, "/v1/debug", require.False},
			{http.MethodGet, "/sqlmetrics", require.False},
			{http.MethodGet, "/v1/users", require.True},
			{http.MethodGet, "/v1/users/1", require.True},
			{http.MethodGet, "/v1/users/1/debug", require.True},
			{http.MethodGet, "/v1/users/1/sqlmetrics", require.True},
		}

		filter := o11y.FilterRoutes("/v1/status", "/v1/debug", "/sqlmetrics")
		for _, tc := range tests {
			tc.assert(t, filter(httptest.NewRequest(tc.method, tc.target, http.NoBody)))
		}
	})

	t.Run("Probes", func(t *testing.T) {
		tests := []struct {
			method string
			target string
			assert require.BoolAssertionFunc
		}{
			{http.MethodGet, "/readyz", require.False},
			{http.MethodGet, "/livez", require.False},
			{http.MethodGet, "/healthz", require.False},
			{http.MethodGet, "/v1/users", require.True},
			{http.MethodGet, "/v1/users/1", require.True},
			{http.MethodGet, "/v1/users/1/debug", require.True},
			{http.MethodGet, "/v1/users/1/sqlmetrics", require.True},
		}

		filter := o11y.FilterProbes
		for _, tc := range tests {
			tc.assert(t, filter(httptest.NewRequest(tc.method, tc.target, http.NoBody)))
		}
	})

	t.Run("Status", func(t *testing.T) {
		tests := []struct {
			method string
			target string
			assert require.BoolAssertionFunc
		}{
			{http.MethodGet, "/v1/status", require.False},
			{http.MethodGet, "/v1/users", require.True},
			{http.MethodGet, "/v1/users/1", require.True},
			{http.MethodGet, "/v1/users/1/debug", require.True},
			{http.MethodGet, "/v1/users/1/sqlmetrics", require.True},
		}

		filter := o11y.FilterStatus
		for _, tc := range tests {
			tc.assert(t, filter(httptest.NewRequest(tc.method, tc.target, http.NoBody)))
		}
	})

	t.Run("Heartbeats", func(t *testing.T) {
		tests := []struct {
			method string
			target string
			assert require.BoolAssertionFunc
		}{
			{http.MethodGet, "/readyz", require.False},
			{http.MethodGet, "/livez", require.False},
			{http.MethodGet, "/healthz", require.False},
			{http.MethodGet, "/v1/status", require.False},
			{http.MethodGet, "/v1/debug", require.True},
			{http.MethodGet, "/", require.True},
			{http.MethodGet, "/v1/users", require.True},
			{http.MethodGet, "/v1/users/1", require.True},
			{http.MethodGet, "/v1/users/1/debug", require.True},
			{http.MethodGet, "/v1/users/1/sqlmetrics", require.True},
		}

		filter := o11y.FilterHeartbeats
		for _, tc := range tests {
			tc.assert(t, filter(httptest.NewRequest(tc.method, tc.target, http.NoBody)))
		}
	})
}
