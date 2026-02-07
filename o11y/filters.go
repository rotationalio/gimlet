package o11y

import "net/http"

// Filter the specified routes from being traced.
func FilterRoutes(routes ...string) Filter {
	exclude := map[string]struct{}{}
	for _, route := range routes {
		exclude[route] = struct{}{}
	}

	return func(r *http.Request) bool {
		_, ok := exclude[r.URL.Path]
		return !ok
	}
}

// Filter kubernetes probe requests from being traced.
func FilterProbes(r *http.Request) bool {
	switch r.URL.Path {
	case "/readyz", "/livez", "/healthz":
		return false
	default:
		return true
	}
}

// Filter status requests from being traced.
func FilterStatus(r *http.Request) bool {
	return r.URL.Path != "/v1/status"
}

// Filter probes and status requests from being traced.
func FilterHeartbeats(r *http.Request) bool {
	switch r.URL.Path {
	case "/readyz", "/livez", "/healthz", "/v1/status":
		return false
	default:
		return true
	}
}
