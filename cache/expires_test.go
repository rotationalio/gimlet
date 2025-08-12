package cache_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/cache"
)

func TestExpires(t *testing.T) {
	lastModified := time.Date(2024, 11, 21, 10, 43, 61, 0, time.UTC)
	expires := lastModified.Add(2 * time.Hour)

	t.Run("Empty", func(t *testing.T) {
		e := &cache.Expires{}
		require.True(t, e.LastModified().IsZero(), "expected zero last modified")
		require.True(t, e.Expires().IsZero(), "expected zero expires")
	})

	t.Run("LastModified", func(t *testing.T) {
		e := &cache.Expires{}
		e.Modified(lastModified, nil)
		require.Equal(t, lastModified, e.LastModified(), "expected last modified to be set")
		require.True(t, e.Expires().IsZero(), "expected zero expires")
	})

	t.Run("LastModifiedBadType", func(t *testing.T) {
		e := &cache.Expires{}
		e.Modified(lastModified, true)
		require.Equal(t, lastModified, e.LastModified(), "expected last modified to be set")
		require.True(t, e.Expires().IsZero(), "expected zero expires")
	})

	t.Run("ExpiresDuration", func(t *testing.T) {
		e := &cache.Expires{}
		e.Modified(lastModified, 2*time.Hour)
		require.Equal(t, lastModified, e.LastModified(), "expected last modified to be set")
		require.Equal(t, expires, e.Expires(), "expected expires to be set from duration")
	})

	t.Run("ExpiresInt64", func(t *testing.T) {
		e := &cache.Expires{}
		e.Modified(lastModified, int64(7200))
		require.Equal(t, lastModified, e.LastModified(), "expected last modified to be set")
		require.Equal(t, expires, e.Expires(), "expected expires to be set from int64 seconds")
	})

	t.Run("ExpiresTime", func(t *testing.T) {
		e := &cache.Expires{}
		e.Modified(lastModified, expires)
		require.Equal(t, lastModified, e.LastModified(), "expected last modified to be set")
		require.Equal(t, expires, e.Expires(), "expected expires to be set from time")
	})
}
