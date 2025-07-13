package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	. "go.rtnl.ai/gimlet/ratelimit"
)

func TestClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Cache", func(t *testing.T) {
		// Create a new ClientIP limiter with a short cache TTL.
		limiter := NewClientIP(Config{
			Type:     TypeIPAddr,
			Limit:    2.0,
			Burst:    8,
			CacheTTL: 100 * time.Millisecond,
		})

		// Test getting/adding IP addresses from multiple go routines.
		requests := make([]*gin.Context, 4)
		for i := 0; i < len(requests); i++ {
			ipaddr := "10.15.100." + strconv.Itoa(i+1)
			c, _ := CreateTestContextWithIP(t, ipaddr)
			requests[i] = c
		}

		// Make 7 requests from all IP addresses.
		// While we're at it, let's also check the double checked locking in Get/Add
		var wg sync.WaitGroup
		for i := 0; i < 7; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, c := range requests {
					allowed, _ := limiter.Allow(c)
					require.True(t, allowed, "expected request from %s to be allowed", c.ClientIP())
				}
			}()
		}

		wg.Wait()

		// The 8th request should be allowed from all IP addresses.
		for _, c := range requests {
			allowed, headers := limiter.Allow(c)
			require.True(t, allowed, "expected request to be allowed")

			require.Contains(t, headers, HeaderLimit, "expected limit header to be set")
			require.Contains(t, headers, HeaderRemaining, "expected remaining header to be set")
			require.Contains(t, headers, HeaderReset, "expected reset header to be set")

			require.Equal(t, "8", headers[HeaderLimit], "expected limit header to match burst size")
			require.Equal(t, "0.00", headers[HeaderRemaining], "expected remaining header to be one less than burst size")

			// Parse the reset header to ensure it's a valid timestamp.
			resetTime, err := ParseReset(headers[HeaderReset])
			require.NoError(t, err, "expected reset header to be a valid timestamp")
			require.WithinDuration(t, time.Now(), resetTime, 500*time.Millisecond)
		}
	})

	t.Run("LimitSingleIP", func(t *testing.T) {
		// Ensure that a single IP address can be rate limited while others are not affected.
		limiter := NewClientIP(Config{
			Type:     TypeIPAddr,
			Limit:    4.0,
			Burst:    16,
			CacheTTL: 100 * time.Millisecond,
		})

		c, _ := CreateTestContextWithIP(t, "10.15.100.1")

		// Make 64 requests from the same IP address.
		for i := 0; i < 64; i++ {
			allowed, _ := limiter.Allow(c)

			if i > 15 {
				require.False(t, allowed, "expected request to not be allowed after burst limit")
			} else {
				require.True(t, allowed, "expected request to be allowed within burst limit")
			}
		}

		// Check the rate limiting headers after the burst limit is exceeded.
		allowed, headers := limiter.Allow(c)
		require.False(t, allowed, "expected request to not be allowed")

		require.Contains(t, headers, HeaderLimit, "expected limit header to be set")
		require.Contains(t, headers, HeaderRemaining, "expected remaining header to be set")
		require.Contains(t, headers, HeaderReset, "expected reset header to be set")

		require.Equal(t, "16", headers[HeaderLimit], "expected limit header to match burst size")
		require.Regexp(t, `-4(8|9).(0|9)(0|9)`, headers[HeaderRemaining], "expected remaining header to be -48.99 or -49.00")

		// Parse the reset header to ensure it's a valid timestamp.
		resetTime, err := ParseReset(headers[HeaderReset])
		require.NoError(t, err, "expected reset header to be a valid timestamp")
		require.WithinDuration(t, time.Now().Add(12*time.Second), resetTime, 1500*time.Millisecond)

		// Other IP addresses should not be affected.
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func(ip int) {
				defer wg.Done()
				c, _ := CreateTestContextWithIP(t, "10.15.100."+strconv.Itoa(ip+2))
				allowed, _ := limiter.Allow(c)
				require.True(t, allowed, "expected request from 10.15.100.%d to be allowed", ip+2)
			}(i)
		}
		wg.Wait()
	})

	t.Run("Cleanup", func(t *testing.T) {
		// Create a new ClientIP limiter with a short cache TTL.
		limiter := NewClientIP(Config{
			Type:     TypeIPAddr,
			Limit:    10.0,
			Burst:    5,
			CacheTTL: 100 * time.Millisecond,
		})

		requests := make([]*gin.Context, 16)
		for i := 0; i < len(requests); i++ {
			ipaddr := "10.15.100." + strconv.Itoa(i+1)
			c, _ := CreateTestContextWithIP(t, ipaddr)
			requests[i] = c
		}

		// Start the cleanup goroutine.
		go limiter.Cleanup()

		for _, c := range requests[:5] {
			limiter.Allow(c)
		}

		require.Equal(t, 5, limiter.Length(), "expected all IP addresses to be added to the cache")
		time.Sleep(50 * time.Millisecond)

		for _, c := range requests[6 : len(requests)-1] {
			limiter.Allow(c)
		}

		time.Sleep(75 * time.Millisecond)
		require.Equal(t, 14, limiter.Length(), "expected some IP addresses to be removed from the cache")

		time.Sleep(125 * time.Millisecond)

		// Assert that the cache is empty after cleanup.
		require.Equal(t, 0, limiter.Length(), "expected all IP addresses to be removed from the cache")
	})
}

func TestGinClientIP(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err, "expected no error when creating request")
	req.RemoteAddr = "10.15.100.128:80"
	req.Header.Set("X-Forwarded-For", "100.101.42.24")

	c.Request = req

	require.Equal(t, "100.101.42.24", c.ClientIP())
}

func CreateTestContextWithIP(t *testing.T, ip string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err, "expected no error when creating request")
	req.RemoteAddr = ip + ":80"
	c.Request = req

	return c, w
}
