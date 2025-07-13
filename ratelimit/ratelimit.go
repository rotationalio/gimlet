package ratelimit

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
)

const (
	HeaderLimit     = "X-RateLimit-Limit"
	HeaderRemaining = "X-RateLimit-Remaining"
	HeaderReset     = "X-RateLimit-Reset"
)

var (
	ErrCreateRateLimiter = errors.New("cannot create rate limiter: no configuration or limiter provided")
	ErrRateLimitExceeded = errors.New("rate limit reached: too many requests")
)

// RateLimit creates a gin middleware that rate limits requests based on the provided
// configuration or limiter. You can also pass nil to use the default configuration.
// Each request is checked if it is allowed by the rate limiter, and if not it aborts
// the request with a 429 Too Many Requests status code. This middleware also sets
// the appropriate headers for rate limiting: X-RateLimit-Limit, X-RateLimit-Remaining,
// and X-RateLimit-Reset. Further, this function also starts a goroutine to clean up the
// rate limiter cache periodically if the limiter supports it.
func RateLimit(confOrLimiter any) (_ gin.HandlerFunc, err error) {
	// Create the limiter from the configuration.
	var limiter Limiter
	if conf, ok := confOrLimiter.(*Config); ok || confOrLimiter == nil {
		if limiter, err = New(conf); err != nil {
			return nil, err
		}
	}

	if rl, ok := confOrLimiter.(Limiter); ok {
		limiter = rl
	}

	if limiter == nil {
		return nil, ErrCreateRateLimiter
	}

	// Run the limiter go routine to cleanup the limiter cache.
	go limiter.Cleanup()

	return func(c *gin.Context) {
		// Check if the request is allowed.
		allowed, headers := limiter.Allow(c)

		// Set the headers for the response.
		for key, value := range headers {
			c.Header(key, value)
		}

		if !allowed {
			gimlet.Abort(c, http.StatusTooManyRequests, ErrRateLimitExceeded)
			return
		}

		c.Next()
	}, nil
}

// Generally speaking the rate limiter headers should be X-RateLimit-Limit,
// X-RateLimit-Remaining, and X-RateLimit-Reset. These are returned in a map from the
// limiter Allow method to set the rate limit headers in the response.
type Headers map[string]string

type Limiter interface {
	Allow(c *gin.Context) (bool, Headers)
	Cleanup()
}

// Creates a new rate limiter based on the provided configuration; returns an error if
// the configuration is invalid. If nil is passed in, the default configuration is used.
// We don't suggest using this function directly, instead use the RateLimit middleware
// function which handles the creation and cleanup of the limiter.
func New(conf *Config) (limiter Limiter, err error) {
	// Use the default configuration if none is provided.
	if conf == nil {
		conf = &DefaultConfig
	}

	if err = conf.Validate(); err != nil {
		return nil, err
	}

	switch conf.Type {
	case TypeIPAddr:
		limiter = &ClientIP{conf: *conf}
	case TypeConstant:
		limiter = NewConstant(*conf)
	case TypeMock:
		limiter = &Mock{conf: *conf, calls: make(map[string]int)}
	}

	return limiter, nil
}

// ParseReset parses the reset header value and returns the timestamp.
func ParseReset(reset string) (time.Time, error) {
	if reset == "" {
		return time.Time{}, nil
	}

	resetInt, err := strconv.ParseInt(reset, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid reset header value: %w", err)
	}

	return time.UnixMilli(resetInt), nil
}
