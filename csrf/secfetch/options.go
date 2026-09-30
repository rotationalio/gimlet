package csrf

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// Holds a middleware setting that can be applied while constructing the handler.
type Option func(*config)

// Stores the policy assembled from middleware options.
type config struct {
	namespace                string
	safeHTTPMethods          []string
	logOnly                  bool
	expectedOrigins          []string
	fallback                 func(*gin.Context) bool
	allowMissingMetadata     bool
	allowUnknownSite         bool
	allowSiteNone            bool
	allowedFetchModes        []string
	allowedFetchDestinations []string
	requireFetchMode         bool
	requireFetchDestination  bool
}

// Applies non-nil settings in order, with later options replacing earlier values.
func configure(options ...Option) config {
	cfg := config{safeHTTPMethods: []string{"GET", "HEAD", "OPTIONS"}}
	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}
	return cfg
}

// WithSafeHTTPMethods sets the HTTP methods that bypass CSRF checks. Only GET,
// HEAD, and OPTIONS are accepted; unsafe methods such as POST can never be added.
// The default allows all three safe methods, while an empty list checks every method.
func WithSafeHTTPMethods(methods []string) Option {
	copyOfMethods := make([]string, 0, len(methods))
	for _, method := range methods {
		switch strings.ToUpper(strings.TrimSpace(method)) {
		case "GET":
			copyOfMethods = append(copyOfMethods, "GET")
		case "HEAD":
			copyOfMethods = append(copyOfMethods, "HEAD")
		case "OPTIONS":
			copyOfMethods = append(copyOfMethods, "OPTIONS")
		}
	}
	return func(cfg *config) {
		cfg.safeHTTPMethods = copyOfMethods
	}
}

// WithLogOnly records requests that the CSRF policy would reject, but allows them
// to continue through the handler chain. Use this to review logs before enforcing
// the policy.
func WithLogOnly(enabled bool) Option {
	return func(cfg *config) {
		cfg.logOnly = enabled
	}
}

// Adds a service-specific prefix to the CSRF error response header. An empty
// value retains the default header; for example, "endeavor" produces
// X-Endeavor-CSRF-Error.
func WithNamespace(namespace string) Option {
	return func(cfg *config) {
		cfg.namespace = namespace
	}
}

// Sets the exact HTTP or HTTPS origins trusted by the policy. The same list is
// used to approve same-site writes and as the allowlist for Origin/Referer
// fallback. Entries should be origins, not URL paths or hostnames.
func WithExpectedOrigins(origins []string) Option {
	copyOfOrigins := append([]string(nil), origins...)
	return func(cfg *config) {
		cfg.expectedOrigins = copyOfOrigins
	}
}

// WithFallback adds an application-defined, already-authenticated bypass only when
// Sec-Fetch-Site, Origin, and Referer are all absent. Use it for verified non-cookie
// authentication or explicit double-cookie verification, not credential presence.
func WithFallback(check func(*gin.Context) bool) Option {
	return func(cfg *config) {
		cfg.fallback = check
	}
}

// Allows state-changing requests with no Sec-Fetch-Site after fallback and
// expected Origin/Referer checks fail. This compatibility relaxation is disabled
// by default.
func WithAllowMissingMetadata(allow bool) Option {
	return func(cfg *config) {
		cfg.allowMissingMetadata = allow
	}
}

// Allows state-changing requests with an unrecognized Sec-Fetch-Site after
// fallback and expected Origin/Referer checks fail. This is disabled by default.
func WithAllowUnknownSite(allow bool) Option {
	return func(cfg *config) {
		cfg.allowUnknownSite = allow
	}
}

// WithAllowSiteNone allows state-changing requests carrying Sec-Fetch-Site: none.
// This is disabled by default.
func WithAllowSiteNone(allow bool) Option {
	return func(cfg *config) {
		cfg.allowSiteNone = allow
	}
}

// Restricts Sec-Fetch-Mode when present. An empty list imposes no restriction;
// a separate setting can require the header.
func WithAllowedFetchModes(modes []string) Option {
	copyOfModes := append([]string(nil), modes...)
	return func(cfg *config) {
		cfg.allowedFetchModes = copyOfModes
	}
}

// Restricts Sec-Fetch-Dest when present. An empty list imposes no restriction;
// a separate setting can require the header.
func WithAllowedFetchDestinations(destinations []string) Option {
	copyOfDestinations := append([]string(nil), destinations...)
	return func(cfg *config) {
		cfg.allowedFetchDestinations = copyOfDestinations
	}
}

// Requires Sec-Fetch-Mode on state-changing requests when enabled.
func WithRequireFetchMode(require bool) Option {
	return func(cfg *config) {
		cfg.requireFetchMode = require
	}
}

// Requires Sec-Fetch-Dest on state-changing requests when enabled.
func WithRequireFetchDestination(require bool) Option {
	return func(cfg *config) {
		cfg.requireFetchDestination = require
	}
}

// Converts configured values into a lookup set, trimming surrounding whitespace.
func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return set
}

// Reports whether a value belongs to a previously constructed lookup set.
func contains(set map[string]struct{}, value string) bool {
	_, ok := set[value]
	return ok
}

// Produces a safe, canonical CSRF error-header name from a namespace.
func namespacedErrorHeader(namespace string) string {
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	if namespace == "" {
		return ErrorHeader
	}

	var normalized strings.Builder
	normalized.Grow(len(namespace))
	for _, char := range namespace {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '-', char == '_':
			normalized.WriteRune(char)
		default:
			normalized.WriteByte('_')
		}
	}
	name := normalized.String()
	return "X-" + strings.ToUpper(name[:1]) + name[1:] + "-CSRF-Error"
}
