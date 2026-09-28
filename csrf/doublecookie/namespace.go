package csrf

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Holds the names of the CSRF cookie and header.
type Namespace struct {
	Cookie          string
	ReferenceCookie string
	Header          string
	ErrorHeader     string
}

var defaultNamespace = Namespace{
	Cookie:          Cookie,
	ReferenceCookie: ReferenceCookie,
	Header:          Header,
	ErrorHeader:     ErrorHeader,
}

// An interface for types that can derive CSRF names from a namespace.
type Namespacer interface {
	Namespace() Namespace
}

// Returns a host-only namespace (prefix "__Host-") from the given namespace.
func hostNamespace(namespace Namespace) Namespace {
	namespace.Cookie = "__Host-" + namespace.Cookie
	namespace.ReferenceCookie = "__Host-" + namespace.ReferenceCookie
	return namespace
}

// NewSecureTokenHandler returns a signed CSRF token handler using the default
// cookie TTL, root path, and host-only cookies. The secret must be at least 32
// bytes long; unlike NewTokenHandler, it does not allow a naive token handler.
func NewSecureTokenHandler(secret []byte, namespace string) (TokenHandler, error) {
	if len(secret) == 0 {
		return nil, ErrNoSignedCSRFSecret
	}

	handler := &SignedCSRFTokens{
		CookieTTL:  CookieTTL,
		CookiePath: "/",
		namespace:  hostNamespace(namesForNamespace(namespace)),
	}
	if err := handler.SetSecret(secret); err != nil {
		return nil, err
	}
	return handler, nil
}

// Returns a CSRF token handler configured to use namespaced cookie and header
// names. The legacy NewTokenHandler constructor remains unchanged and uses the
// legacy names.
func NewTokenHandlerWithNamespace(cookieTTL time.Duration, path string, domains []string, secret []byte, namespace string) (TokenHandler, error) {
	return newTokenHandler(cookieTTL, path, domains, secret, namespace)
}

// Creates CSRF middleware using names derived from namespace. It is useful with
// custom TokenVerifier implementations that do not expose CSRFNames.
func DoubleCookieWithNamespace(verifier TokenVerifier, namespace string) gin.HandlerFunc {
	return doubleCookie(verifier, namesForNamespace(namespace))
}

// Sets namespaced CSRF cookies using the supplied token generator.
func SetDoubleCookieTokenWithNamespace(c *gin.Context, generator TokenGenerator, path string, domains []string, expires time.Time, namespace string) (err error) {
	return setDoubleCookieToken(c, generator, path, domains, expires, namesForNamespace(namespace))
}

// Derives safe cookie and header names from a namespace. An empty namespace
// preserves the legacy names. Namespace values are trimmed, lowercased, and
// non-alphanumeric characters (other than '-' and '_') are replaced with '_'.
func namesForNamespace(namespace string) Namespace {
	namespace = normalizeNamespace(namespace)
	if namespace == "" {
		return defaultNamespace
	}

	return Namespace{
		Cookie:          namespace + "_" + Cookie,
		ReferenceCookie: namespace + "_" + ReferenceCookie,
		Header:          "X-" + strings.ToUpper(namespace[:1]) + namespace[1:] + "-CSRF-Token",
		ErrorHeader:     "X-" + strings.ToUpper(namespace[:1]) + namespace[1:] + "-CSRF-Error",
	}
}

// Returns a safe, canonical namespace for CSRF names. Empty and whitespace-only
// namespaces are normalized to the legacy behavior.
func normalizeNamespace(namespace string) string {
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	if namespace == "" {
		return ""
	}

	var normalized strings.Builder
	normalized.Grow(len(namespace))
	for _, char := range namespace {
		switch {
		case char >= 'a' && char <= 'z':
			normalized.WriteRune(char)
		case char >= '0' && char <= '9':
			normalized.WriteRune(char)
		case char == '-' || char == '_':
			normalized.WriteRune(char)
		default:
			normalized.WriteByte('_')
		}
	}
	return normalized.String()
}
