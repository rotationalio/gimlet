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
	// Error header and value used to indicate a rejected CSRF request.
	HeaderError          = "X-CSRF-Error"
	ErrorRequestRejected = "csrf_request_rejected"

	// Constants for headers used in Fetch Metadata CSRF requests.
	HeaderOrigin       = "Origin"
	HeaderReferer      = "Referer"
	HeaderSecFetchSite = "Sec-Fetch-Site"
	HeaderSecFetchMode = "Sec-Fetch-Mode"
	HeaderSecFetchDest = "Sec-Fetch-Dest"
)

// Describes a request rejected by the CSRF policy in the response body.
var ErrCSRFVerification = errors.New("csrf verification failed for request")

// Returns Gin middleware that applies the Fetch Metadata CSRF policy.
//
//   - Safe methods (GET, HEAD, and OPTIONS; unless otherwise configured) pass
//     through.
//   - Fetch mode and destination headers are checked if configured.
//   - cross-site requests are always rejected.
//   - same-origin requests are always allowed.
//   - same-site requests are allowed with an exact match from a configured
//     expected origin to a safe origin header.
//   - Unknown site values are allowed only when configured.
//   - Configured fallback checks are final, and only applied when no Fetch
//     Metadata or safe origin headers are present.
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

		// Check for the Sec-Fetch-Site header.
		site, sitePresent, siteValid := singleHeader(c.Request, HeaderSecFetchSite)
		knownSite := siteValid && isKnownSite(site)

		// Without a recognized site value we have several fallback options to
		// check.
		if !sitePresent || !knownSite {
			// Use Origin or Referer if available, rejecting on a mismatch to
			// either.
			originPresent := len(c.Request.Header.Values(HeaderOrigin)) > 0
			refererPresent := len(c.Request.Header.Values(HeaderReferer)) > 0
			if originPresent || refererPresent {
				if !originOrRefererAllowed(c.Request, origins) {
					reject(c, errorHeader, cfg.logOnly, "origin_not_allowed")
					return
				}
				c.Next()
				return
			}

			// Options only apply when we do not have a trusted Origin/Referer.
			if (!sitePresent && cfg.allowMissingMetadata) || (sitePresent && cfg.allowUnknownSite) {
				c.Next()
				return
			}

			// The fallback is only for requests with no Fetch Metadata, Origin,
			// or Referer headers.
			if !sitePresent && cfg.fallback != nil {
				if cfg.fallback(c) {
					c.Next()
					return
				}
				reject(c, errorHeader, cfg.logOnly, "fallback_failed")
				return
			}

			// If we have no fallback, then reject for the site header being
			// missing or unknown.
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
			if headerOriginAllowed(c.Request, HeaderOrigin, false, origins) {
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
		if origin, ok := canonicalOrigin(c.GetHeader(HeaderReferer), true); ok {
			refererOrigin = origin
		}

		rlog.WarnAttrs(c.Request.Context(), "CSRF request would be rejected",
			slog.String("reason", reason),
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.String("sec_fetch_site", c.GetHeader(HeaderSecFetchSite)),
			slog.String("sec_fetch_mode", c.GetHeader(HeaderSecFetchMode)),
			slog.String("sec_fetch_dest", c.GetHeader(HeaderSecFetchDest)),
			slog.String("origin", c.GetHeader(HeaderOrigin)),
			slog.Bool("referer_present", len(c.Request.Header.Values(HeaderReferer)) > 0),
			slog.String("referer_origin", refererOrigin),
		)
		c.Next()
		return
	}

	c.Header(errorHeader, ErrorRequestRejected)
	gimlet.Abort(c, http.StatusForbidden, ErrCSRFVerification)
}
