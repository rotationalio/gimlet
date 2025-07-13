package ratelimit

import (
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Mock implements the Limiter interface for package testing purposes.
type Mock struct {
	sync.RWMutex
	conf      Config
	calls     map[string]int
	OnAllow   func(c *gin.Context) (bool, Headers)
	OnCleanup func()
}

func (r *Mock) Allow(c *gin.Context) (bool, Headers) {
	r.incr("Allow")
	r.RLock()
	defer r.RUnlock()
	if r.OnAllow != nil {
		return r.OnAllow(c)
	}
	panic("OnAllow mock callback not set")
}

func (r *Mock) Cleanup() {
	r.incr("Cleanup")
	r.RLock()
	defer r.RUnlock()
	if r.OnCleanup != nil {
		r.OnCleanup()
	}
}

func (r *Mock) Reset() {
	r.Lock()
	defer r.Unlock()
	r.calls = nil
	r.calls = make(map[string]int)
	r.OnAllow = nil
	r.OnCleanup = nil
}

func (r *Mock) AssertCalls(t *testing.T, method string, expected int) {
	t.Helper()

	r.RLock()
	defer r.RUnlock()
	require.Equal(t, expected, r.calls[method], "expected %d calls to %s, got %d", expected, method, r.calls[method])
}

func (r *Mock) incr(method string) {
	r.Lock()
	defer r.Unlock()
	if r.calls == nil {
		r.calls = make(map[string]int)
	}
	r.calls[method]++
}
