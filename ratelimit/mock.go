package ratelimit

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Mock implements the Limiter interface for package testing purposes.
type Mock struct {
	conf      Config
	calls     map[string]int
	OnAllow   func(c *gin.Context) (bool, Headers)
	OnCleanup func()
}

func (r *Mock) Allow(c *gin.Context) (bool, Headers) {
	r.calls["Allow"]++
	if r.OnAllow != nil {
		return r.OnAllow(c)
	}
	panic("OnAllow mock callback not set")
}

func (r *Mock) Cleanup() {
	r.calls["Cleanup"]++
	if r.OnCleanup != nil {
		r.OnCleanup()
	}
}

func (r *Mock) Reset() {
	r.calls = nil
	r.calls = make(map[string]int)
	r.OnAllow = nil
	r.OnCleanup = nil
}

func (r *Mock) AssertCalls(t *testing.T, method string, expected int) {
	t.Helper()
	require.Equal(t, expected, r.calls[method], "expected %d calls to %s, got %d", expected, method, r.calls[method])
}
