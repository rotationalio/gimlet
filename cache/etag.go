package cache

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"sync"
)

// ETag is a thread-safe mechanism to compute etags for resources and implements the
// ETagger interface for the cache-control middleware. Etags can be computed using a
// SHA-1 hash of the resource data, or set manually.
type ETag struct {
	sync.RWMutex
	value string
}

func (e *ETag) ETag() string {
	e.RLock()
	defer e.RUnlock()
	return e.value
}

func (e *ETag) Compute(data []byte) {
	hash := sha1.New()
	hash.Write(data)
	e.Set(hex.EncodeToString(hash.Sum(nil)))
}

func (e *ETag) Set(value string) {
	e.Lock()
	defer e.Unlock()
	e.value = value
}

// WeakEtag is a thread-safe mechanism to compute weak etags for resources. It
// implements the ETagger interface for the cache-control middleware. Weak etags are
// similar to regular etags but are prefixed with "W/" to indicate that collisions are
// possible. Weak etags should be used in performance critical environments. Weak etags
// can be computed using an md5 hash of the resource data, or set manually.
type WeakEtag struct {
	sync.RWMutex
	value string
}

func (e *WeakEtag) ETag() string {
	e.RLock()
	defer e.RUnlock()
	return e.value
}

func (e *WeakEtag) Compute(data []byte) {
	hash := md5.New()
	hash.Write(data)
	e.Set(hex.EncodeToString(hash.Sum(nil)))
}

func (e *WeakEtag) Set(value string) {
	value = `W/` + strconv.Quote(value)

	e.Lock()
	defer e.Unlock()
	e.value = value
}
