package secure

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
)

func Secure(c *Config) gin.HandlerFunc {
	if c == nil {
		c = &Config{
			ContentTypeNosniff: true,
		}
	}

	c.SetDefaults()
	headers := make(map[string]string, 4)

	if c.ContentTypeNosniff {
		headers[HeaderContentTypeNosniff] = NoSniff
	}

	if c.CrossOriginOpenerPolicy != NoPolicy {
		headers[HeaderCrossOriginOpenerPolicy] = c.CrossOriginOpenerPolicy
	}

	if c.ReferrerPolicy != NoPolicy {
		headers[HeaderReferrerPolicy] = c.ReferrerPolicy
	}

	if directive := c.HSTS.Directive(); directive != "" {
		headers[HeaderStrictTransportSecurity] = directive
	}

	if directive := c.ContentSecurityPolicy.Directive(); directive != "" {
		headers[HeaderContentSecurityPolicy] = directive
	}

	if directive := c.ContentSecurityPolicyReportOnly.Directive(); directive != "" {
		headers[HeaderCSPReportOnly] = directive
	}

	if len(c.ReportingEndpoints) > 0 {
		headers[HeaderReportingEndpoints] = ReportingEndpoints(c.ReportingEndpoints)
	}

	return func(c *gin.Context) {
		for k, v := range headers {
			c.Header(k, v)
		}
		c.Next()
	}
}

//===========================================================================
// Header Constants
//===========================================================================

const (
	HeaderContentTypeNosniff      = "X-Content-Type-Options"
	HeaderReferrerPolicy          = "Referrer-Policy"
	HeaderCrossOriginOpenerPolicy = "Cross-Origin-Opener-Policy"
	HeaderStrictTransportSecurity = "Strict-Transport-Security"
	HeaderReportingEndpoints      = "Reporting-Endpoints"
	HeaderContentSecurityPolicy   = "Content-Security-Policy"
	HeaderCSPReportOnly           = "Content-Security-Policy-Report-Only"
)

//===========================================================================
// Policy Constants
//===========================================================================

// ContentTypeNoSniff
const NoSniff = "nosniff"

// Referrer Policy Options
const (
	NoPolicy                    = "none"
	NoReferrer                  = "no-referrer"
	NoReferrerWhenDowngrade     = "no-referrer-when-downgrade"
	Origin                      = "origin"
	OriginWhenCrossOrigin       = "origin-when-cross-origin"
	SameOrigin                  = "same-origin"
	StrictOrigin                = "strict-origin"
	StrictOriginWhenCrossOrigin = "strict-origin-when-cross-origin"
	UnsafeURL                   = "unsafe-url"
)

// List of all supported Referrer-Policy options
var ReferrerPolicies = [9]string{
	// No Referrer Policy is set.
	NoPolicy,

	// Instructs the browser to send no referrer for links clicked on this site.
	NoReferrer,

	// Instructs the browser to send the full URL as the referrer,
	// but only when no protocol downgrade occurs.
	NoReferrerWhenDowngrade,

	// Instructs the browser to send only the origin, not the full URL, as the referrer
	Origin,

	// Instructs the browser to send the full URL when performing a same-origin request,
	// but only send the origin when performing a cross-origin request.
	OriginWhenCrossOrigin,

	// Instructs the browser to send the full URL when performing a same-origin request,
	// but not send the Referer header when performing a cross-origin request.
	SameOrigin,

	// Instructs the browser to send only the origin, not the full URL, and to send no
	// referrer when a protocol downgrade occurs.
	StrictOrigin,

	// Instructs the browser to send the full URL when the link is same-origin and no
	// protocol downgrade occurs; send only the origin when the link is cross-origin and
	// no protocol downgrade occurs; and no referrer when a protocol downgrade occurs.
	StrictOriginWhenCrossOrigin,

	// Instructs the browser to always send the full URL as the referrer,
	UnsafeURL,
}

// Cross-Origin-Opener-Policy Options
const (
	SameOriginAllowPopups = "same-origin-allow-popups"
	NoOpenerAllowPopups   = "noopener-allow-popups"
	UnsafeNone            = "unsafe-none"
)

// List of all supported Cross-Origin-Opener-Policy options
var CrossOriginOpenerPolicies = [5]string{
	// No Cross-Origin-Opener-Policy is set.
	NoPolicy,

	// Isolates the browsing context exclusively to same-origin documents. Cross-origin
	// documents are not loaded in the same browsing context.
	// This is the default and most secure option.
	SameOrigin,

	// Isolates the browsing context to same-origin documents or those which either
	// don’t set COOP or which opt out of isolation by setting a COOP of unsafe-none.
	SameOriginAllowPopups,

	// Documents are always opened in a new browsing context, except when opened by
	// navigating from a document that also has noopener-allow-popups.
	NoOpenerAllowPopups,

	// Allows the document to be added to its opener’s browsing context group unless
	// the opener itself has a COOP of same-origin or same-origin-allow-popups.
	UnsafeNone,
}

func ReferrerPolicy(policy string) (string, error) {
	policy = strings.TrimSpace(strings.ToLower(policy))
	for _, p := range ReferrerPolicies {
		if policy == p {
			return policy, nil
		}
	}
	return "", fmt.Errorf("unknown referrer policy %q", policy)
}

func OpenerPolicy(policy string) (string, error) {
	policy = strings.TrimSpace(strings.ToLower(policy))
	for _, p := range CrossOriginOpenerPolicies {
		if policy == p {
			return policy, nil
		}
	}
	return "", fmt.Errorf("unknown cross-origin opener policy %q", policy)
}

func ReportingEndpoints(endpoints map[string]string) string {
	// Reporting endpoints are always sorted alphabetically by name
	directives := make([]string, 0, len(endpoints))
	urls := make([]string, 0, len(endpoints))

	// Because we're taking input from a map, directives are already duplicate-free.
	for directive, url := range endpoints {
		if len(directives) == 0 {
			directives = append(directives, directive)
			urls = append(urls, url)
			continue
		}

		// Use binary search to find the insertion point
		i, _ := slices.BinarySearch(directives, directive)
		directives = append(directives, "")
		copy(directives[i+1:], directives[i:])
		directives[i] = directive

		urls = append(urls, "")
		copy(urls[i+1:], urls[i:])
		urls[i] = url
	}

	sb := new(strings.Builder)
	first := true

	for i, directive := range directives {
		if !first {
			sb.WriteString(", ")
		}
		first = false

		fmt.Fprintf(sb, `%s="%s"`, directive, urls[i])
	}

	return sb.String()
}
