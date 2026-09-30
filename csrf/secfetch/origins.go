package csrf

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Normalizes configured origins and excludes entries that are not valid HTTP(S) origins.
func expectedOriginSet(expected []string) map[string]struct{} {
	origins := make(map[string]struct{}, len(expected))
	for _, origin := range expected {
		if normalized, ok := canonicalOrigin(origin, false); ok {
			origins[normalized] = struct{}{}
		}
	}
	return origins
}

// Checks Origin first and consults Referer only when Origin was not supplied.
func originOrRefererAllowed(request *http.Request, origins map[string]struct{}) bool {
	if len(request.Header.Values(HeaderOrigin)) > 0 {
		return headerOriginAllowed(request, HeaderOrigin, false, origins)
	}
	return headerOriginAllowed(request, HeaderReferer, true, origins)
}

// Validates one origin-bearing header against the trusted origin set.
func headerOriginAllowed(request *http.Request, header string, allowPath bool, origins map[string]struct{}) bool {
	values := request.Header.Values(header)
	if len(values) != 1 {
		return false
	}
	origin, ok := canonicalOrigin(values[0], allowPath)
	if !ok {
		return false
	}
	_, ok = origins[origin]
	return ok
}

// Converts an HTTP(S) URL to its origin tuple, optionally ignoring Referer path,
// query, and fragment components.
func canonicalOrigin(raw string, allowPath bool) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Opaque != "" || u.User != nil {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return "", false
	}
	if !allowPath && (u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "") {
		return "", false
	}

	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", false
		}
		if scheme == "http" && portNumber == 80 || scheme == "https" && portNumber == 443 {
			port = ""
		}
	}

	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, true
}
