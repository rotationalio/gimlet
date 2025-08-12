package cache_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/cache"
	"go.rtnl.ai/x/httpcc"
)

func TestCacheControl(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		ctrl := &cache.CacheControl{}
		require.Empty(t, ctrl.Directives(), "expected empty directives")

		ctrl.SetDirectives(httpcc.ResponseBuilder{})
		require.Empty(t, ctrl.Directives(), "expected empty directives after setting empty")
	})

	t.Run("SetDirectives", func(t *testing.T) {
		ctrl := &cache.CacheControl{}
		directives := httpcc.ResponseBuilder{
			Public:         true,
			MustRevalidate: true,
		}
		ctrl.SetDirectives(directives)
		require.Equal(t, "must-revalidate, public", ctrl.Directives(), "expected directives to be set")
	})

	t.Run("SetMaxAge", func(t *testing.T) {
		ctrl := &cache.CacheControl{}
		directives := httpcc.ResponseBuilder{
			Private: true,
		}
		ctrl.SetDirectives(directives)

		t.Run("Past", func(t *testing.T) {
			testCases := []any{
				int64(-3600),
				-1 * time.Hour,
				time.Duration(-10231223),
				time.Time{},
				time.Now().Add(-1 * time.Hour),
				int64(0),
				uint64(0),
				time.Duration(0),
				&(time.Time{}),
				nil,
				"",
				true,
				false,
				struct{}{},
			}

			for _, tc := range testCases {
				ctrl.SetMaxAge(tc)
				require.Equal(t, "max-age=0, private", ctrl.Directives(), "expected max-age=0 for negative duration")
			}
		})

		t.Run("Future", func(t *testing.T) {
			expires := time.Now().Add(2 * time.Hour).Truncate(time.Second)

			testCases := []any{
				int64(7199),
				uint64(7199),
				7199 * time.Second,
				expires,
				&expires,
			}

			for _, tc := range testCases {
				ctrl.SetMaxAge(tc)
				require.Equal(t, "max-age=7199, private", ctrl.Directives(), "expected max-age=7200 for 2 hours")
			}
		})
	})

	t.Run("SetSMaxAge", func(t *testing.T) {
		ctrl := &cache.CacheControl{}
		directives := httpcc.ResponseBuilder{
			Public: true,
		}
		ctrl.SetDirectives(directives)

		t.Run("Past", func(t *testing.T) {
			testCases := []any{
				int64(-3600),
				-1 * time.Hour,
				time.Duration(-10231223),
				time.Time{},
				time.Now().Add(-1 * time.Hour),
				int64(0),
				uint64(0),
				time.Duration(0),
				&(time.Time{}),
				nil,
				"",
				true,
				false,
				struct{}{},
			}

			for _, tc := range testCases {
				ctrl.SetSMaxAge(tc)
				require.Equal(t, "s-maxage=0, public", ctrl.Directives(), "expected s-maxage=0 for negative duration")
			}
		})

		t.Run("Future", func(t *testing.T) {
			expires := time.Now().Add(2 * time.Hour).Truncate(time.Second)

			testCases := []any{
				int64(7199),
				uint64(7199),
				7199 * time.Second,
				expires,
				&expires,
			}
			for _, tc := range testCases {
				ctrl.SetSMaxAge(tc)
				require.Equal(t, "s-maxage=7199, public", ctrl.Directives(), "expected s-maxage=7200 for 2 hours")
			}
		})
	})

	t.Run("SetExpires", func(t *testing.T) {
		ctrl := &cache.CacheControl{}
		directives := httpcc.ResponseBuilder{
			Private: true,
			Public:  true,
		}
		ctrl.SetDirectives(directives)

		expires := time.Now().Add(2 * time.Hour).Truncate(time.Second)
		ctrl.SetMaxAge(expires)
		ctrl.SetSMaxAge(expires.Add(-1 * time.Hour)) // should be ignored
		require.Equal(t, "max-age=7199, s-maxage=3599, private, public", ctrl.Directives(), "expected expires to be set")
	})
}
