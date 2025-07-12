package ratelimit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/ratelimit"
)

func TestDefaultConfig(t *testing.T) {
	require.NoError(t, ratelimit.DefaultConfig.Validate())
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		conf ratelimit.Config
		err  error
	}{
		{ratelimit.Config{Type: "", Limit: 2.5, Burst: 14, CacheTTL: 10 * time.Minute}, ratelimit.ErrInvalidType},
		{ratelimit.Config{Type: "foo", Limit: 5.2, Burst: 100, CacheTTL: 10 * time.Minute}, ratelimit.ErrInvalidType},
		{ratelimit.Config{Type: "ipaddr", Limit: 0, Burst: 14, CacheTTL: 10 * time.Minute}, ratelimit.ErrLimitRequired},
		{ratelimit.Config{Type: "constant", Limit: -1, Burst: 14, CacheTTL: 10 * time.Minute}, ratelimit.ErrLimitRequired},
		{ratelimit.Config{Type: "ipaddr", Limit: 6, Burst: -1, CacheTTL: 10 * time.Minute}, ratelimit.ErrBurstRequired},
		{ratelimit.Config{Type: "constant", Limit: 4, Burst: 0, CacheTTL: 10 * time.Minute}, ratelimit.ErrBurstRequired},
		{ratelimit.Config{Type: "ipaddr", Limit: 3, Burst: 14, CacheTTL: 0}, ratelimit.ErrCacheTTLRequired},
		{ratelimit.Config{Type: "constant", Limit: 3, Burst: 14, CacheTTL: -1}, ratelimit.ErrCacheTTLRequired},
		{ratelimit.Config{Type: "ipaddr", Limit: 10, Burst: 30, CacheTTL: 10 * time.Minute}, nil},
		{ratelimit.Config{Type: "constant", Limit: 10, Burst: 30, CacheTTL: 10 * time.Minute}, nil},
	}

	for _, test := range tests {
		require.ErrorIs(t, test.conf.Validate(), test.err)
	}
}
