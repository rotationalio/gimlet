package cache

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/x/httpcc"
)

// If the request has an ETag header, it will be checked against the Etagger interface.
// If the ETag matches, a 304 Not Modified response is sent. The ETag header is also
// included in the response.
type ETagger interface {
	ETag() string
	ComputeETag([]byte)
	SetETag(string)
}

// If the request has an If-Modified-Since or If-Unmodified-Since header, it will be
// checked against the Expirer interface using the LastModified timestamp. The Expires
// header is also included in the response.
type Expirer interface {
	LastModified() time.Time
	Expires() time.Time
	Modified(time.Time, any)
}

// This interface adds the cache control directives in the response to the gin context.
// The directives specified are then set in the response headers.
type CacheController interface {
	Directives() string
	SetMaxAge(any)
	SetSMaxAge(any)
}

// Cache Control middleware handles cache control headers on both the request and the
// response. If the request has a cache control header, the etag or the expiration is
// checked and a 304 Not Modified response is sent if appropriate. Otherwise, it sets
// the appropriate cache control headers on the response.
//
// NOTE: the behavior of this middleware is controlled by the interface specified above.
// For example, if the ETagger interface is implemented, the ETag header will be checked
// and set in the response, but if it is not implemented, the ETag header in a request
// will be ignored.
func Control(handler any) gin.HandlerFunc {
	etagger, useEtag := handler.(ETagger)
	expirer, useExpires := handler.(Expirer)
	cc, useCC := handler.(CacheController)

	return func(c *gin.Context) {
		directives, err := httpcc.Request(c.Request)
		if err != nil {
			gimlet.Abort(c, http.StatusBadRequest, err)
			return
		}

		if useEtag {
			if etag := etagger.ETag(); etag != "" {
				if match, ok := directives.IfNoneMatch(); ok && etag == match {
					gimlet.Abort(c, http.StatusNotModified, nil)
					return
				}

				// Quote the ETag value if it's not marked as weak
				if !strings.HasPrefix(etag, "W/") {
					etag = strconv.Quote(etag)
				}

				c.Header(httpcc.ETag, etag)
			}
		}

		if useExpires {
			if lastModified := expirer.LastModified(); !lastModified.IsZero() {
				if match, ok := directives.IfModifiedSince(); ok && (lastModified.Equal(match) || lastModified.Before(match)) {
					gimlet.Abort(c, http.StatusNotModified, nil)
					return
				}

				if match, ok := directives.IfUnmodifiedSince(); ok && lastModified.After(match) {
					gimlet.Abort(c, http.StatusPreconditionFailed, nil)
					return
				}

				c.Header(httpcc.LastModified, lastModified.UTC().Format(http.TimeFormat))
			}

			if expires := expirer.Expires(); !expires.IsZero() {
				if expires.After(time.Now()) {
					c.Header(httpcc.Expires, expires.UTC().Format(http.TimeFormat))
				} else {
					c.Header(httpcc.Expires, "0")
				}
			}
		}

		if useCC {
			if directives := cc.Directives(); directives != "" {
				c.Header(httpcc.CacheControl, directives)
			}
		}

		gimlet.Set(c, gimlet.KeyCacheControl, directives)
		gimlet.Set(c, gimlet.KeyCacheHandler, handler)
		c.Next()
	}
}

// RequestDirectives retrieves the parsed cache control directives from the gin context.
func RequestDirectives(c *gin.Context) *httpcc.RequestDirective {
	if val, ok := gimlet.Get(c, gimlet.KeyCacheControl); ok {
		if directives, ok := val.(*httpcc.RequestDirective); ok {
			return directives
		}
	}
	return nil
}

// SetETag sets the ETag header on the handler in the gin context. If the handler does
// not implement the ETagger interface, this function simply sets the ETag header.
func SetETag(c *gin.Context, etag string) {
	if val, ok := gimlet.Get(c, gimlet.KeyCacheHandler); ok {
		if etagger, ok := val.(ETagger); ok {
			etagger.SetETag(etag)
		}
	}
	c.Header(httpcc.ETag, etag)
}

// ComputeETag computes the ETag for the data and sets it on the handler in the gin
// as well as on the header of the response. If the handler does not implement the
// ETagger interface, this function does nothing (not even set the header).
func ComputeETag(c *gin.Context, data []byte) {
	if val, ok := gimlet.Get(c, gimlet.KeyCacheHandler); ok {
		if etagger, ok := val.(ETagger); ok {
			etagger.ComputeETag(data)
			c.Header(httpcc.ETag, etagger.ETag())
		}
	}
}

// Modified does a lot of work on the handler in the gin context. It sets the
// Last-Modified and Expires headers based on the Expirer interface. If the handler
// implements the CacheController interface, it will set the MaxAge directive to the
// duration or expires timestamp as well. Note that this method will not set the
// s-maxage directive even if the cache controller is public. That must be set in a
// separate call.
func Modified(c *gin.Context, lastModified time.Time, durationOrExpires any) {
	if val, ok := gimlet.Get(c, gimlet.KeyCacheHandler); ok {
		if expirer, ok := val.(Expirer); ok {
			expirer.Modified(lastModified, durationOrExpires)

			if lastModified := expirer.LastModified(); !lastModified.IsZero() {
				c.Header(httpcc.LastModified, lastModified.UTC().Format(http.TimeFormat))
			}

			if expires := expirer.Expires(); !expires.IsZero() {
				if expires.After(time.Now()) {
					c.Header(httpcc.Expires, expires.UTC().Format(http.TimeFormat))
				} else {
					c.Header(httpcc.Expires, "0")
				}
			}
		}

		if cc, ok := val.(CacheController); ok {
			cc.SetMaxAge(durationOrExpires)
			if directives := cc.Directives(); directives != "" {
				c.Header(httpcc.CacheControl, directives)
			}
		}
	}
}

// SetSMaxAge sets the s-maxage directive on the handler in the gin context and on the
// headers of the outgoing response. If the handler does not implement the
// CacheController interface, this function does nothing.
func SetSMaxAge(c *gin.Context, sMaxAge any) {
	if val, ok := gimlet.Get(c, gimlet.KeyCacheHandler); ok {
		if cc, ok := val.(CacheController); ok {
			cc.SetSMaxAge(sMaxAge)
			if directives := cc.Directives(); directives != "" {
				c.Header(httpcc.CacheControl, directives)
			}
		}
	}
}
