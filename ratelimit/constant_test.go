package ratelimit_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/ratelimit"
)

func TestConstant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Single", func(t *testing.T) {
		// A single request should be allowed.
		limit := ratelimit.NewConstant(ratelimit.Config{Limit: 4.0, Burst: 16})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		allowed, headers := limit.Allow(c)
		require.True(t, allowed, "expected request to be allowed")

		require.Contains(t, headers, ratelimit.HeaderLimit, "expected limit header to be set")
		require.Contains(t, headers, ratelimit.HeaderRemaining, "expected remaining header to be set")
		require.Contains(t, headers, ratelimit.HeaderReset, "expected reset header to be set")

		require.Equal(t, "16", headers[ratelimit.HeaderLimit], "expected limit header to match burst size")
		require.Equal(t, "15.00", headers[ratelimit.HeaderRemaining], "expected remaining header to be one less than burst size")

		// Parse the reset header to ensure it's a valid timestamp.
		resetTime, err := ratelimit.ParseReset(headers[ratelimit.HeaderReset])
		require.NoError(t, err, "expected reset header to be a valid timestamp")
		require.WithinDuration(t, time.Now(), resetTime, 500*time.Millisecond)
	})

	t.Run("Burst", func(t *testing.T) {
		// Test that multiple requests within the burst limit are allowed.
		// A single request should be allowed.
		limit := ratelimit.NewConstant(ratelimit.Config{Limit: 4.0, Burst: 16})

		for i := 0; i < 15; i++ {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			allowed, _ := limit.Allow(c)
			require.True(t, allowed, "expected request to be allowed")
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		allowed, headers := limit.Allow(c)
		require.True(t, allowed, "expected request to be allowed")

		require.Contains(t, headers, ratelimit.HeaderLimit, "expected limit header to be set")
		require.Contains(t, headers, ratelimit.HeaderRemaining, "expected remaining header to be set")
		require.Contains(t, headers, ratelimit.HeaderReset, "expected reset header to be set")

		require.Equal(t, "16", headers[ratelimit.HeaderLimit], "expected limit header to match burst size")
		require.Regexp(t, `0.0(0|1)`, headers[ratelimit.HeaderRemaining], "expected remaining header to be zero after all tokens were used")

		// Parse the reset header to ensure it's a valid timestamp.
		resetTime, err := ratelimit.ParseReset(headers[ratelimit.HeaderReset])
		require.NoError(t, err, "expected reset header to be a valid timestamp")
		require.WithinDuration(t, time.Now(), resetTime, 500*time.Millisecond)
	})

	t.Run("Limit", func(t *testing.T) {
		// Test that multiple requests within the burst limit are allowed.
		// A single request should be allowed.
		limit := ratelimit.NewConstant(ratelimit.Config{Limit: 4.0, Burst: 16})

		for i := 0; i < 64; i++ {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			allowed, _ := limit.Allow(c)
			if i > 15 {
				require.False(t, allowed, "expected request to not be allowed after burst limit")
			} else {
				require.True(t, allowed, "expected request to be allowed within burst limit")
			}
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		allowed, headers := limit.Allow(c)
		require.False(t, allowed, "expected request to not be allowed")

		require.Contains(t, headers, ratelimit.HeaderLimit, "expected limit header to be set")
		require.Contains(t, headers, ratelimit.HeaderRemaining, "expected remaining header to be set")
		require.Contains(t, headers, ratelimit.HeaderReset, "expected reset header to be set")

		require.Equal(t, "16", headers[ratelimit.HeaderLimit], "expected limit header to match burst size")
		require.Regexp(t, `-4(8|9).(0|9)(0|9)`, headers[ratelimit.HeaderRemaining], "expected remaining header to be -48.99 or -49.00")

		// Parse the reset header to ensure it's a valid timestamp.
		resetTime, err := ratelimit.ParseReset(headers[ratelimit.HeaderReset])
		require.NoError(t, err, "expected reset header to be a valid timestamp")
		require.WithinDuration(t, time.Now().Add(12*time.Second), resetTime, 1500*time.Millisecond)
	})

	t.Run("Block", func(t *testing.T) {
		// Test that requests are blocked when there is no rate limit available.
		// A single request should be allowed.
		limit := ratelimit.NewConstant(ratelimit.Config{Limit: 0, Burst: 0})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		allowed, headers := limit.Allow(c)
		require.False(t, allowed, "expected request to not be allowed")

		require.Contains(t, headers, ratelimit.HeaderLimit, "expected limit header to be set")
		require.Contains(t, headers, ratelimit.HeaderRemaining, "expected remaining header to be set")
		require.NotContains(t, headers, ratelimit.HeaderReset, "expected no reset header to be set")

		require.Equal(t, "0", headers[ratelimit.HeaderLimit], "expected limit header to match burst size")
		require.Equal(t, "0.00", headers[ratelimit.HeaderRemaining], "expected remaining header to be one less than burst size")
	})
}
