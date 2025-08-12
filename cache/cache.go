package cache

import (
	"net/http"
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
}

// If the request has an If-Modified-Since or If-Unmodified-Since header, it will be
// checked against the Expirer interface using the LastModified timestamp. The Expires
// header is also included in the response.
type Expirer interface {
	LastModified() time.Time
	Expires() time.Time
}

// This interface adds the cache control directives in the response to the gin context.
// The directives specified are then set in the response headers.
type CacheController interface {
	Directives() string
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
			etag := etagger.ETag()
			if match, ok := directives.IfNoneMatch(); ok && etag == match {
				gimlet.Abort(c, http.StatusNotModified, nil)
				return
			}
			c.Header(httpcc.ETag, etag)
		}

		if useExpires {
			if lastModified := expirer.LastModified(); !lastModified.IsZero() {
				if match, ok := directives.IfModifiedSince(); ok && lastModified.Before(match) {
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
		c.Next()
	}
}

func RequestDirectives(c *gin.Context) *httpcc.RequestDirective {
	if val, ok := gimlet.Get(c, gimlet.KeyCacheControl); ok {
		if directives, ok := val.(*httpcc.RequestDirective); ok {
			return directives
		}
	}
	return nil
}
