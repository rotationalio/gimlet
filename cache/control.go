package cache

import (
	"sync"
	"time"

	"go.rtnl.ai/x/httpcc"
)

// CacheControl is a thread-safe structure to manage Cache-Control headers for
// resources and implements the CacheController interface for the cache-control
// middleware.
type CacheControl struct {
	sync.RWMutex
	builder *httpcc.ResponseBuilder
}

var _ CacheController = (*CacheControl)(nil)

func (c *CacheControl) Directives() string {
	c.RLock()
	defer c.RUnlock()
	if c.builder == nil {
		return ""
	}
	return c.builder.String()
}

func (c *CacheControl) SetMaxAge(maxAge any) {
	switch v := maxAge.(type) {
	case time.Duration:
		var seconds uint64
		if v < 0 {
			seconds = 0
		} else {
			seconds = uint64(v.Seconds())
		}
		c.Lock()
		c.builder.SetMaxAge(seconds)
		c.Unlock()
	case uint64:
		c.Lock()
		c.builder.SetMaxAge(v)
		c.Unlock()
	case int64:
		var seconds uint64
		if v < 0 {
			seconds = 0
		} else {
			seconds = uint64(v)
		}
		c.Lock()
		c.builder.SetMaxAge(seconds)
		c.Unlock()
	case time.Time:
		if v.IsZero() || v.Before(time.Now()) {
			c.Lock()
			c.builder.SetMaxAge(0)
			c.Unlock()
			return
		}

		c.Lock()
		c.builder.SetExpires(v)
		c.Unlock()
	case *time.Time:
		if v == nil || v.IsZero() || v.Before(time.Now()) {
			c.Lock()
			c.builder.SetMaxAge(0)
			c.Unlock()
			return
		}

		c.Lock()
		c.builder.SetExpires(*v)
		c.Unlock()
	}
}

func (c *CacheControl) SetSMaxAge(sMaxAge any) {
	switch v := sMaxAge.(type) {
	case time.Duration:
		var seconds uint64
		if v < 0 {
			seconds = 0
		} else {
			seconds = uint64(v.Seconds())
		}
		c.Lock()
		c.builder.SetSMaxAge(seconds)
		c.Unlock()
	case uint64:
		c.Lock()
		c.builder.SetSMaxAge(v)
		c.Unlock()
	case int64:
		var seconds uint64
		if v < 0 {
			seconds = 0
		} else {
			seconds = uint64(v)
		}
		c.Lock()
		c.builder.SetSMaxAge(seconds)
		c.Unlock()
	case time.Time:
		if v.IsZero() || v.Before(time.Now()) {
			c.Lock()
			c.builder.SetSMaxAge(0)
			c.Unlock()
			return
		}

		c.Lock()
		c.builder.SetSExpires(v)
		c.Unlock()
	case *time.Time:
		if v == nil || v.IsZero() || v.Before(time.Now()) {
			c.Lock()
			c.builder.SetSMaxAge(0)
			c.Unlock()
			return
		}

		c.Lock()
		c.builder.SetSExpires(*v)
		c.Unlock()
	}
}

func (c *CacheControl) SetDirectives(directives httpcc.ResponseBuilder) {
	c.Lock()
	defer c.Unlock()
	c.builder = &directives
}
