package ratelimit_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/ratelimit"
)

var (
	mockConfig = &ratelimit.Config{
		Type:     ratelimit.TypeMock,
		Limit:    10.0,
		Burst:    5,
		CacheTTL: 1 * time.Minute,
	}
)

func TestRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter, err := ratelimit.New(mockConfig)
	require.NoError(t, err, "expected no error when creating mock limiter")

	mock, ok := limiter.(*ratelimit.Mock)
	require.True(t, ok, "expected limiter to be of type Mock")

	ratelimitter, err := ratelimit.RateLimit(mock)
	require.NoError(t, err, "expected no error when creating rate limit handler with mock limiter")

	router := gin.New()
	router.Use(ratelimitter)
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": true})
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	t.Run("Allow", func(t *testing.T) {
		t.Cleanup(mock.Reset)
		mock.OnAllow = func(c *gin.Context) (bool, ratelimit.Headers) {
			return true, ratelimit.Headers{"X-RateLimit-Limit": "16", "X-RateLimit-Remaining": "12"}
		}

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
		require.NoError(t, err, "expected no error when creating request")
		reply, err := ts.Client().Do(req)
		require.NoError(t, err, "expected no error when sending request")

		require.Equal(t, http.StatusOK, reply.StatusCode, "expected status code 200 OK")
		require.Equal(t, "16", reply.Header.Get(ratelimit.HeaderLimit), "expected X-RateLimit-Limit header to be set")
		require.Equal(t, "12", reply.Header.Get(ratelimit.HeaderRemaining), "expected X-RateLimit-Remaining header to be set")

		mock.AssertCalls(t, "Allow", 1)
	})

	t.Run("NotAllowed", func(t *testing.T) {
		t.Cleanup(mock.Reset)
		reset := time.Now().Add(60 * time.Second).Unix()
		mock.OnAllow = func(c *gin.Context) (bool, ratelimit.Headers) {
			return false, ratelimit.Headers{"X-RateLimit-Limit": "16", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": fmt.Sprintf("%d", reset)}
		}

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
		require.NoError(t, err, "expected no error when creating request")
		reply, err := ts.Client().Do(req)
		require.NoError(t, err, "expected no error when sending request")

		require.Equal(t, http.StatusTooManyRequests, reply.StatusCode, "expected status code 429 Too Many Requests")
		require.Equal(t, "16", reply.Header.Get(ratelimit.HeaderLimit), "expected X-RateLimit-Limit header to be set")
		require.Equal(t, "0", reply.Header.Get(ratelimit.HeaderRemaining), "expected X-RateLimit-Remaining header to be set")
		require.Equal(t, fmt.Sprintf("%d", reset), reply.Header.Get(ratelimit.HeaderReset), "expected X-RateLimit-Reset header to be set")

		mock.AssertCalls(t, "Allow", 1)
	})

	t.Run("NoHeaders", func(t *testing.T) {
		t.Cleanup(mock.Reset)
		mock.OnAllow = func(c *gin.Context) (bool, ratelimit.Headers) {
			return true, nil // No headers set
		}

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
		require.NoError(t, err, "expected no error when creating request")
		reply, err := ts.Client().Do(req)
		require.NoError(t, err, "expected no error when sending request")

		require.Equal(t, http.StatusOK, reply.StatusCode, "expected status code 200 OK")
		require.Empty(t, reply.Header.Get(ratelimit.HeaderLimit), "expected X-RateLimit-Limit header to be empty")
		require.Empty(t, reply.Header.Get(ratelimit.HeaderRemaining), "expected X-RateLimit-Remaining header to be empty")
		require.Empty(t, reply.Header.Get(ratelimit.HeaderReset), "expected X-RateLimit-Reset header to be empty")

		mock.AssertCalls(t, "Allow", 1)
	})
}

func TestRateLimitConstruct(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		handler, err := ratelimit.RateLimit(nil)
		require.NoError(t, err, "expected no error when creating rate limit handler nil")
		require.NotNil(t, handler, "expected non-nil handler when creating rate limit handler with nil limiter")
	})

	t.Run("Config", func(t *testing.T) {
		handler, err := ratelimit.RateLimit(&ratelimit.DefaultConfig)
		require.NoError(t, err, "expected no error when creating rate limit handler with valid config")
		require.NotNil(t, handler, "expected non-nil handler when creating rate limit handler with valid config")
	})

	t.Run("Limiter", func(t *testing.T) {
		limiter, err := ratelimit.New(mockConfig)
		require.NoError(t, err, "expected no error when creating mock limiter")

		handler, err := ratelimit.RateLimit(limiter)
		require.NoError(t, err, "expected no error when creating rate limit handler with mock limiter")
		require.NotNil(t, handler, "expected non-nil handler when creating rate limit handler with mock limiter")

		time.Sleep(100 * time.Millisecond) // Allow cleanup goroutine to run
		limiter.(*ratelimit.Mock).AssertCalls(t, "Cleanup", 1)
	})

	t.Run("BadType", func(t *testing.T) {
		handler, err := ratelimit.RateLimit(432)
		require.ErrorIs(t, err, ratelimit.ErrCreateRateLimiter, "expected validation error for empty config")
		require.Nil(t, handler, "expected nil handler for empty config")
	})

	t.Run("BadConfig", func(t *testing.T) {
		empty := &ratelimit.Config{}
		target := empty.Validate()
		require.Error(t, target, "expected error for empty config")

		handler, err := ratelimit.RateLimit(empty)
		require.ErrorIs(t, err, target, "expected validation error for empty config")
		require.Nil(t, handler, "expected nil handler for empty config")
	})

	t.Run("NewConstantLimiter", func(t *testing.T) {
		limiter, err := ratelimit.New(&ratelimit.Config{
			Type:     ratelimit.TypeConstant,
			Limit:    10.0,
			Burst:    5,
			CacheTTL: 1 * time.Minute,
		})
		require.NoError(t, err, "expected no error when creating constant limiter")
		_, ok := limiter.(*ratelimit.Constant)
		require.True(t, ok, "expected limiter to be of type Constant")
	})

	t.Run("NewClientIPLimiter", func(t *testing.T) {
		limiter, err := ratelimit.New(&ratelimit.Config{
			Type:     ratelimit.TypeIPAddr,
			Limit:    10.0,
			Burst:    5,
			CacheTTL: 1 * time.Minute,
		})
		require.NoError(t, err, "expected no error when creating ipaddr limiter")
		_, ok := limiter.(*ratelimit.ClientIP)
		require.True(t, ok, "expected limiter to be of type ClientIP")
	})
}

func TestParseReset(t *testing.T) {
	t.Run("ValidReset", func(t *testing.T) {
		reset := "1633036800000" // Example timestamp in milliseconds
		expectedTime := time.UnixMilli(1633036800000)

		parsedTime, err := ratelimit.ParseReset(reset)
		require.NoError(t, err, "expected no error when parsing valid reset")
		require.Equal(t, expectedTime, parsedTime, "expected parsed time to match expected time")
	})

	t.Run("EmptyReset", func(t *testing.T) {
		reset := ""
		parsedTime, err := ratelimit.ParseReset(reset)
		require.NoError(t, err, "expected no error when parsing empty reset")
		require.Equal(t, time.Time{}, parsedTime, "expected parsed time to be zero value for empty reset")
	})

	t.Run("InvalidReset", func(t *testing.T) {
		reset := "invalid"
		_, err := ratelimit.ParseReset(reset)
		require.Error(t, err, "expected error when parsing invalid reset")
	})
}
