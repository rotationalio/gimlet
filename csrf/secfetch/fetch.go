package csrf

import (
	"net/http"
	"strings"
)

// Enforces configured Fetch Mode and Fetch Destination allowlists and requirements.
func fetchContextAllowed(request *http.Request, modes, destinations map[string]struct{}, cfg config) bool {
	if len(modes) > 0 || cfg.requireFetchMode {
		mode, present, valid := singleHeader(request, "Sec-Fetch-Mode")
		if !valid || cfg.requireFetchMode && !present {
			return false
		}
		if present && len(modes) > 0 && !contains(modes, mode) {
			return false
		}
	}

	if len(destinations) > 0 || cfg.requireFetchDestination {
		destination, present, valid := singleHeader(request, "Sec-Fetch-Dest")
		if !valid || cfg.requireFetchDestination && !present {
			return false
		}
		if present && len(destinations) > 0 && !contains(destinations, destination) {
			return false
		}
	}

	return true
}

// Returns a trimmed header value and distinguishes absent headers from malformed
// or duplicate values.
func singleHeader(request *http.Request, name string) (value string, present, valid bool) {
	values := request.Header.Values(name)
	if len(values) == 0 {
		return "", false, true
	}
	if len(values) != 1 {
		return "", true, false
	}
	value = strings.TrimSpace(values[0])
	return value, true, value != ""
}

// Identifies whether the method is in the configured safe-method set.
func isSafeMethod(method string, safeMethods map[string]struct{}) bool {
	return contains(safeMethods, method)
}

// Reports whether a Sec-Fetch-Site value is one of the standardized values.
func isKnownSite(site string) bool {
	switch site {
	case "same-origin", "same-site", "cross-site", "none":
		return true
	default:
		return false
	}
}
