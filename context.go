package gimlet

import (
	"context"

	"github.com/gin-gonic/gin"
)

// ContextKey is used to define keys for all gimlet context values so that keys can be
// shared across packages without collisions.
type ContextKey uint8

const (
	KeyUnknown ContextKey = iota
	KeyRequestID
	KeyUserClaims
	KeyAccessToken
	KeyCacheControl
)

var contextKeyNames = [5]string{"unknown", "requestID", "userClaims", "accessToken", "cacheControl"}

func (c ContextKey) String() string {
	if int(c) < len(contextKeyNames) {
		return contextKeyNames[c]
	}
	return contextKeyNames[0]
}

// Sets a value in the gin context using a gimlet context key.
func Set(c *gin.Context, key ContextKey, value interface{}) {
	c.Set(key.String(), value)
}

// Gets a value from the gin context using a gimlet context key; if the key does not
// exist, it checks the request context for the value. If a context is passed in, it
// will retrieve the value from the request context instead of the gin context.
func Get(c any, key ContextKey) (interface{}, bool) {
	switch ctx := c.(type) {
	case *gin.Context:
		// If c is a gin.Context, first try to get the value from the gin
		if value, exists := ctx.Get(key.String()); exists {
			return value, true
		}
		return Get(ctx.Request.Context(), key)
	case context.Context:
		value := ctx.Value(key)
		return value, value != nil
	default:
		return nil, false
	}
}

// SetContext updates the request context with a new value for the specified key.
func SetContext(c *gin.Context, key ContextKey, value interface{}) {
	// HACK: this creates a shallow copy of the request, which might cause issues?
	ctx := context.WithValue(c.Request.Context(), key, value)
	c.Request = c.Request.WithContext(ctx)
}

// SetBoth updates both the gin context and the request context with a new value for the specified key.
func SetBoth(c *gin.Context, key ContextKey, value interface{}) {
	Set(c, key, value)
	SetContext(c, key, value)
}
