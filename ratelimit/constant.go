package ratelimit

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type Constant struct {
	conf  Config
	limit *rate.Limiter
	burst string
}

// NewConstant creates a new constant rate limiter with the given configuration.
// It uses a token bucket algorithm with a fixed rate and burst size. If the number of
// requests continues to exceed the limit, the limiter will increase the delay for
// subsequent requests until the rate limit is no longer exceeded.
// NOTE: config type and CacheTTL are ignored for constant rate limiters.
func NewConstant(conf Config) *Constant {
	limiter := &Constant{
		conf:  conf,
		limit: rate.NewLimiter(rate.Limit(conf.Limit), conf.Burst),
	}

	limiter.burst = strconv.Itoa(limiter.limit.Burst())
	return limiter
}

func (r *Constant) Allow(c *gin.Context) (_ bool, headers Headers) {
	reservation := r.limit.Reserve()
	delay := reservation.Delay()

	headers = Headers{
		HeaderLimit:     r.burst,
		HeaderRemaining: fmt.Sprintf("%0.2f", r.limit.Tokens()),
	}

	if ok := reservation.OK(); ok {
		headers[HeaderReset] = fmt.Sprintf("%d", time.Now().Add(delay).UnixMilli())
	}

	return delay == 0, headers
}

// Constant rate limiters do not require a cleanup go routine, so this is a no-op.
func (r *Constant) Cleanup() {}
