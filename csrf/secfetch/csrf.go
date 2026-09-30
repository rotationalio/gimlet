// Package csrf provides Fetch Metadata CSRF protection middleware for Gin.
package csrf

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/x/rlog"
)

const (
	// Identifies a rejected CSRF request in the response header.
	ErrorHeader = "X-CSRF-Error"
	// Provides the stable machine-readable signal for a rejected request.
	ErrorRequestRejected = "csrf_request_rejected"
)

// Describes a request rejected by the CSRF policy in the response body.
var ErrCSRFVerification = errors.New("csrf verification failed for request")

// Returns Gin middleware that applies the Fetch Metadata CSRF policy.
// Safe methods (GET, HEAD, and OPTIONS) pass through. For state-changing methods,
// cross-site requests are denied, same-origin requests are allowed, and same-site
// requests require an exact match in the configured expected origins. Requests
// without usable Fetch Metadata must prove an expected Origin or Referer unless
// explicitly relaxed by an option or accepted by the configured fallback.
func Middleware(options ...Option) gin.HandlerFunc {
	cfg := configure(options...)
	origins := expectedOriginSet(cfg.expectedOrigins)
	allowedModes := stringSet(cfg.allowedFetchModes)
	allowedDestinations := stringSet(cfg.allowedFetchDestinations)
	safeMethods := stringSet(cfg.safeHTTPMethods)
	errorHeader := namespacedErrorHeader(cfg.namespace)

	return func(c *gin.Context) {
		// Allow safe methods, no matter what.
		if isSafeMethod(c.Request.Method, safeMethods) {
			c.Next()
			return
		}

		// Check the Sec-Fetch-Mode and Sec-Fetch-Dest headers if configured,
		// even if we don't later find a Sec-Fetch-Site header.
		if !fetchContextAllowed(c.Request, allowedModes, allowedDestinations, cfg) {
			reject(c, errorHeader, cfg.logOnly, "fetch_context_not_allowed")
			return
		}

		// Check the Sec-Fetch-Site header.
		site, sitePresent, siteValid := singleHeader(c.Request, "Sec-Fetch-Site")
		knownSite := siteValid && isKnownSite(site)

		// We do not have a Sec-Fetch-Site header, so fall back to checking the
		// Origin or Referer headers.
		if !sitePresent || !knownSite {
			// Fallback to checking the Origin or Referer headers.
			if originOrRefererAllowed(c.Request, origins) {
				c.Next()
				return
			}

			// If we have no helpful, secure header to read, then use the
			// fallback CSRF check if available.
			originPresent := len(c.Request.Header.Values("Origin")) > 0
			refererPresent := len(c.Request.Header.Values("Referer")) > 0
			if !sitePresent && !originPresent && !refererPresent && cfg.fallback != nil && cfg.fallback(c) {
				c.Next()
				return
			}

			// Allow the request with a missing or unknown site if we have
			// configured it.
			if !sitePresent && cfg.allowMissingMetadata || sitePresent && cfg.allowUnknownSite {
				c.Next()
				return
			}

			// Reject otherwise.
			reason := "unknown_site"
			if !sitePresent {
				reason = "missing_site"
			}
			reject(c, errorHeader, cfg.logOnly, reason)
			return
		}

		// Check the site against the configured allowed sites. At this point,
		// we are sure that site is a valid Sec-Fetch-Site value from the spec.
		switch site {
		case "same-origin":
			// Always allow same-origin.
			c.Next()
		case "same-site":
			// Allow same-site if the origin is allowed.
			if headerOriginAllowed(c.Request, "Origin", false, origins) {
				c.Next()
				return
			}
			reject(c, errorHeader, cfg.logOnly, "same_site_origin_not_allowed")
		case "cross-site":
			// Always reject cross-site.
			reject(c, errorHeader, cfg.logOnly, "cross_site")
		case "none":
			// Allow none if configured.
			if cfg.allowSiteNone {
				c.Next()
				return
			}
			reject(c, errorHeader, cfg.logOnly, "site_none")
		}
	}
}

// Logs or rejects a request that failed the configured CSRF policy.
func reject(c *gin.Context, errorHeader string, logOnly bool, reason string) {
	if logOnly {
		refererOrigin := ""
		if origin, ok := canonicalOrigin(c.GetHeader("Referer"), true); ok {
			refererOrigin = origin
		}

		rlog.WarnAttrs(c.Request.Context(), "CSRF request would be rejected",
			slog.String("reason", reason),
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.String("sec_fetch_site", c.GetHeader("Sec-Fetch-Site")),
			slog.String("sec_fetch_mode", c.GetHeader("Sec-Fetch-Mode")),
			slog.String("sec_fetch_dest", c.GetHeader("Sec-Fetch-Dest")),
			slog.String("origin", c.GetHeader("Origin")),
			slog.Bool("referer_present", len(c.Request.Header.Values("Referer")) > 0),
			slog.String("referer_origin", refererOrigin),
		)
		c.Next()
		return
	}

	c.Header(errorHeader, ErrorRequestRejected)
	gimlet.Abort(c, http.StatusForbidden, ErrCSRFVerification)
}
