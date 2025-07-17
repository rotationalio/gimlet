package gimlet_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/ulid"
)

func TestContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mkctx := func() *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		return c
	}

	t.Run("Set", func(t *testing.T) {
		c := mkctx()
		tests := []struct {
			key   gimlet.ContextKey
			value interface{}
		}{
			{gimlet.KeyRequestID, ulid.Make()},
			{gimlet.KeyUserClaims, 42},
			{gimlet.KeyAccessToken, "foo"},
		}

		for _, tc := range tests {
			gimlet.Set(c, tc.key, tc.value)
			val, exists := c.Get(tc.key.String())
			require.True(t, exists, "expected value to be set in gin context")
			require.Equal(t, tc.value, val, "expected value to match set value")

			ctxval := c.Request.Context().Value(tc.key)
			require.Nil(t, ctxval, "expected value to not be set in request context")
		}
	})

	t.Run("SetContext", func(t *testing.T) {
		c := mkctx()
		tests := []struct {
			key   gimlet.ContextKey
			value interface{}
		}{
			{gimlet.KeyRequestID, ulid.Make()},
			{gimlet.KeyUserClaims, 42},
			{gimlet.KeyAccessToken, "foo"},
		}

		for _, tc := range tests {
			gimlet.SetContext(c, tc.key, tc.value)

			val, exists := c.Get(tc.key.String())
			require.False(t, exists, "expected value to not be set in gin context")
			require.Nil(t, val, "expected value to be nil")

			ctxval := c.Request.Context().Value(tc.key)
			require.NotNil(t, ctxval, "expected value to be set in request context")
			require.Equal(t, tc.value, ctxval, "expected value to match set value in request context")
		}
	})

	t.Run("SetBoth", func(t *testing.T) {
		c := mkctx()
		tests := []struct {
			key   gimlet.ContextKey
			value interface{}
		}{
			{gimlet.KeyRequestID, ulid.Make()},
			{gimlet.KeyUserClaims, 42},
			{gimlet.KeyAccessToken, "foo"},
		}

		for _, tc := range tests {
			gimlet.SetBoth(c, tc.key, tc.value)

			val, exists := c.Get(tc.key.String())
			require.True(t, exists, "expected value to be set in gin context")
			require.Equal(t, tc.value, val, "expected value to match set value")

			ctxval := c.Request.Context().Value(tc.key)
			require.NotNil(t, ctxval, "expected value to be set in request context")
			require.Equal(t, tc.value, ctxval, "expected value to match set value in request context")
		}
	})

	t.Run("Get", func(t *testing.T) {
		c := mkctx()
		requestID := ulid.Make()
		gimlet.Set(c, gimlet.KeyRequestID, requestID)
		gimlet.Set(c, gimlet.KeyUserClaims, 42)
		gimlet.SetContext(c, gimlet.KeyUserClaims, 24)
		gimlet.SetContext(c, gimlet.KeyAccessToken, "foo")

		// Can get a value from the gin context when it is not on the request context
		val, exists := gimlet.Get(c, gimlet.KeyRequestID)
		require.True(t, exists, "expected value to be found in gin context")
		require.Equal(t, requestID, val, "expected value to match request ID")

		// Gets the value from the gin context not the request context
		val, exists = gimlet.Get(c, gimlet.KeyUserClaims)
		require.True(t, exists, "expected value to be found in gin context")
		require.Equal(t, 42, val, "expected value to match user claims")

		// Gets the value from the request context if it doesn't exist in the gin context
		val, exists = gimlet.Get(c, gimlet.KeyAccessToken)
		require.True(t, exists, "expected value to be found in request context")
		require.Equal(t, "foo", val, "expected value to match access token")

		// Returns not exists when the key is not set
		val, exists = gimlet.Get(c, gimlet.KeyUnknown)
		require.False(t, exists, "expected value to not be found for unknown key")
		require.Nil(t, val, "expected value to be nil for unknown key")

		// Test with a non-gin context
		ctx := context.WithValue(context.Background(), gimlet.KeyRequestID, requestID)
		val, exists = gimlet.Get(ctx, gimlet.KeyRequestID)
		require.True(t, exists, "expected value to be found in request context")
		require.Equal(t, requestID, val, "expected value to match request ID from context")

		val, exists = gimlet.Get(ctx, gimlet.KeyUserClaims)
		require.False(t, exists, "expected value to not be found for user claims in request context")
		require.Nil(t, val, "expected value to be nil for user claims in request context")

		// Test with a non-context type
		val, exists = gimlet.Get("not a context", gimlet.KeyRequestID)
		require.False(t, exists, "expected value to not be found for non-context type")
		require.Nil(t, val, "expected value to be nil for non-context type")
	})
}
