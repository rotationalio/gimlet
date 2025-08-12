package cache

import (
	"sync"
	"time"
)

// Expires is a thread-safe mechanism to manage Last-Modified and Expires headers for
// resources and implements the Expirer interface for the cache-control middleware.
// The Last-Modified timestamp is set when the resource is created or updated. The
// Expires timestamp can be computed from a max-age duration, or set manually.
type Expires struct {
	sync.RWMutex
	lastModified time.Time
	expires      time.Time
}

var _ Expirer = (*Expires)(nil)

// Modified the last modified timestamp and optionally the expiration timestamp. The
// second parameter should either be a time.Duration to compute the expiration, an
// int64 duration in seconds, or a time.Time to set the expiration directly. If the
// second parameter is nil, the expiration is not set.
func (e *Expires) Modified(lastModified time.Time, durationOrExpires any) {
	var expires time.Time
	switch v := durationOrExpires.(type) {
	case time.Duration:
		expires = lastModified.Add(v)
	case int64:
		expires = lastModified.Add(time.Duration(v) * time.Second)
	case time.Time:
		expires = v
	}

	lastModified = lastModified.Truncate(time.Second).UTC()
	expires = expires.Truncate(time.Second).UTC()

	e.Lock()
	defer e.Unlock()
	e.lastModified = lastModified
	e.expires = expires
}

func (e *Expires) LastModified() time.Time {
	e.RLock()
	defer e.RUnlock()
	return e.lastModified
}

func (e *Expires) Expires() time.Time {
	e.RLock()
	defer e.RUnlock()
	return e.expires
}
