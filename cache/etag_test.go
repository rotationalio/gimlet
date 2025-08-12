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
		e.Set("test-etag")
		require.Equal(t, `test-etag`, e.ETag(), "expected etag to be set")
	})

}
