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
)

var DefaultConfig = Config{
	Type:     TypeConstant,
	Limit:    4.0,
	Burst:    32,
	CacheTTL: 10 * time.Minute,
}

type Config struct {
	Type     string        `default:"constant" desc:"type of rate limiter to use; either ipaddr or constant"`
	Limit    float64       `default:"4.0" desc:"number of tokens that can be added to the ratelimit token bucket per second"`
	Burst    int           `default:"32" desc:"maximum number of tokens/requests in the ratelimit token bucket"`
	CacheTTL time.Duration `split_words:"true" default:"10m" desc:"interval at which the ratelimit token bucket is cleaned up, removing old IP addresses"`
}

func (c Config) Validate() error {
	switch {
	case c.Type != TypeIPAddr && c.Type != TypeConstant && c.Type != TypeMock:
		return ErrInvalidType
	case c.Limit <= 0:
		return ErrLimitRequired
	case c.Burst <= 0:
		return ErrBurstRequired
	case c.CacheTTL <= 0:
		return ErrCacheTTLRequired
	default:
		return nil
	}
}
