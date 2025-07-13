package ratelimit

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ClientIP is a rate limiter that controls how frequently requests can be made from a
// single IP address using the gin.Context's ClientIP method (which also respects
// X-Forwarded-For headers). Each IP address is given its own rate limit token bucket
// specified by the Config. This is useful for limiting abuse from IP addresses involved
// in a DDoS attack while allowing legitimate traffic to continue.
//
// The rate limiter implements a cleanup go routine to periodically clean up the
// rate limit cache to ensure that IP addresses that have not made requests recently
// are removed and prevent memory leaks.
type ClientIP struct {
	sync.RWMutex
	conf   Config
	cache  map[string]*ipaddr
	ticker *time.Ticker
}

type ipaddr struct {
	sync.RWMutex
	limiter  *Constant
	lastSeen time.Time
}

// NewClientIP creates a new ClientIP rate limiter with the given configuration.
// It uses a token bucket algorithm with a fixed rate and burst size. If the number of
// requests from a specific IP address continues to exceed the limit, the limiter
// will increase the delay for subsequent requests until the rate limit is no longer
// exceeded.
//
// NOTE: config type is ignored for ClientIP rate limiters
func NewClientIP(conf Config) *ClientIP {
	limiter := &ClientIP{
		conf:   conf,
		cache:  make(map[string]*ipaddr),
		ticker: time.NewTicker(conf.CacheTTL),
	}
	return limiter
}

func (r *ClientIP) Allow(c *gin.Context) (bool, Headers) {
	ip := r.Get(c.ClientIP())
	return ip.Allow(c)
}

func (ip *ipaddr) Allow(c *gin.Context) (bool, Headers) {
	ip.Lock()
	defer ip.Unlock()

	allowed, headers := ip.limiter.Allow(c)
	ip.lastSeen = time.Now()
	return allowed, headers
}

// GetLimiter returns the rate limiter for the provided IP address if it exists.
// Otherwise calls AddIP to add IP address to the map.
func (r *ClientIP) Get(addr string) *ipaddr {
	// Performs double check locking to ensure that the IP address is added only once.
	// This is the first read lock to check if the IP address exists.
	r.RLock()
	ip, ok := r.cache[addr]

	if !ok {
		// The second double check lock happens in r.Add
		r.RUnlock()
		return r.Add(addr)
	}

	r.RUnlock()
	return ip
}

// Add adds a new IP address rate limiter to the cache if it does not already exist.
func (r *ClientIP) Add(addr string) *ipaddr {
	r.Lock()
	defer r.Unlock()

	// Here is the second check, e.g. the double check
	if ip, ok := r.cache[addr]; ok {
		return ip
	}

	ip := &ipaddr{
		limiter:  NewConstant(r.conf),
		lastSeen: time.Now(),
	}

	r.cache[addr] = ip
	return ip
}

// Returns the number of IP addresses in the cache.
func (r *ClientIP) Length() int {
	r.RLock()
	defer r.RUnlock()
	return len(r.cache)
}

func (r *ClientIP) Cleanup() {
	for {
		// Wait for the ticker to tick.
		ts := <-r.ticker.C

		// Compute the expiration time for the cache.
		expires := ts.Add(-1 * r.conf.CacheTTL)
		removals := make([]string, 0)

		// Loop through the cache to determine which IP addresses should be removed.
		r.Lock()
		for addr, ip := range r.cache {
			ip.RLock()
			if ip.lastSeen.Before(expires) {
				removals = append(removals, addr)
			}
			ip.RUnlock()
		}
		r.Unlock()

		// Remove all IP addresses that have not been seen recently.
		for _, addr := range removals {
			r.Lock()
			delete(r.cache, addr)
			r.Unlock()
		}
	}
}
