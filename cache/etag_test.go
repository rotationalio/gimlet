package cache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEtag(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		e := &ETag{}
		require.Equal(t, "", e.ETag(), "expected empty etag")
	})

	t.Run("Set", func(t *testing.T) {
		e := &ETag{}
		e.SetETag("test-etag")
		require.Equal(t, `test-etag`, e.ETag(), "expected etag to be set")
	})

	t.Run("Compute", func(t *testing.T) {
		e := &ETag{}
		data := []byte("test data")
		e.ComputeETag(data)
		require.Equal(t, "f48dd853820860816c75d54d0f584dc863327a7c", e.ETag(), "expected etag to be computed from data")
	})
}

func TestWeakEtag(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		e := &WeakEtag{}
		require.Equal(t, "", e.ETag(), "expected empty weak etag")
	})

	t.Run("Set", func(t *testing.T) {
		e := &WeakEtag{}
		e.SetETag("test-etag")
		require.Equal(t, `W/"test-etag"`, e.ETag(), "expected etag to be set")
	})

	t.Run("Compute", func(t *testing.T) {
		e := &WeakEtag{}
		data := []byte("test data")
		e.ComputeETag(data)
		require.Equal(t, `W/"eb733a00c0c9d336e65691a37ab54293"`, e.ETag(), "expected etag to be computed from data")
	})
}
