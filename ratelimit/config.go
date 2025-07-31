package ratelimit

import (
	"errors"
	"time"
)

var (
	ErrInvalidType      = errors.New("invalid configuration: ratelimit type must be either ipaddr or constant")
	ErrLimitRequired    = errors.New("invalid configuration: ratelimit per-second limit must be greater than 0")
	ErrBurstRequired    = errors.New("invalid configuration: ratelimit burst must be greater than 0 or all requests will be blocked")
	ErrCacheTTLRequired = errors.New("invalid configuration: ratelimit cache TTL must be greater than 0")
)

const (
	TypeIPAddr   = "ipaddr"
	TypeConstant = "constant"
	TypeMock     = "mock"
	TypeNone     = "none"
)

var DefaultConfig = Config{
	Type:      TypeConstant,
	PerSecond: 4.0,
	Burst:     32,
	CacheTTL:  10 * time.Minute,
}

type Config struct {
	Type      string        `default:"constant" desc:"type of rate limiter to use; either ipaddr or constant"`
	PerSecond float64       `default:"32.0" split_words:"true" desc:"number of tokens that can be added to the ratelimit token bucket per second"`
	Burst     int           `default:"128" desc:"maximum number of tokens/requests in the ratelimit token bucket"`
	CacheTTL  time.Duration `default:"10m" split_words:"true" desc:"interval at which the ratelimit token bucket is cleaned up, removing old IP addresses"`
}

func (c Config) Validate() error {
	switch {
	case c.Type != TypeIPAddr && c.Type != TypeConstant && c.Type != TypeMock && c.Type != TypeNone:
		return ErrInvalidType
	case c.PerSecond <= 0:
		return ErrLimitRequired
	case c.Burst <= 0:
		return ErrBurstRequired
	case c.CacheTTL <= 0:
		return ErrCacheTTLRequired
	default:
		return nil
	}
}
