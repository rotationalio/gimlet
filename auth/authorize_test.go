package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/gimlet/auth"
)

func TestAuthorize(t *testing.T) {
	mkctx := func(permissions ...string) (*gin.Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Accept", "application/json")

		if len(permissions) > 0 {
			claims := &auth.Claims{
				Permissions: permissions,
			}
			gimlet.Set(c, gimlet.KeyUserClaims, claims)
		}

		return c, w
	}

	middleware := auth.Authorize("foo:read", "foo:write")

	t.Run("Unauthorized", func(t *testing.T) {
		c, w := mkctx()
		middleware(c)
		require.Equal(t, 401, w.Code)
	})

	t.Run("Forbidden", func(t *testing.T) {
		c, w := mkctx("bar:read")
		middleware(c)
		require.Equal(t, 403, w.Code)
	})

	t.Run("Authorized", func(t *testing.T) {
		c, w := mkctx("foo:read", "foo:write", "bar:read", "bar:write")
		middleware(c)
		require.Equal(t, 200, w.Code)
	})

	t.Run("WrongType", func(t *testing.T) {
		c, w := mkctx("foo:read", "foo:write")
		gimlet.Set(c, gimlet.KeyUserClaims, "not-a-claims-object")
		middleware(c)
		require.Equal(t, 401, w.Code)
	})
}
