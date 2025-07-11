package gimlet_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet"
)

func TestAbort(t *testing.T) {
	router := gin.New()
	router.GET("/e1", func(c *gin.Context) {
		gimlet.Abort(c, 400, errors.New("test error"))
	})

	router.GET("/e2", func(c *gin.Context) {
		gimlet.Abort(c, 400, "test error")
	})

	srv := httptest.NewServer(router)
	defer srv.Close()

	client := srv.Client()

	t.Run("JSON", func(t *testing.T) {
		for _, ep := range []string{"/e1", "/e2"} {
			req, err := http.NewRequest("GET", srv.URL+ep, nil)
			require.NoError(t, err)

			req.Header.Set("Accept", "application/json")
			rep, err := client.Do(req)
			require.NoError(t, err)

			AssertErrorReply(t, rep, http.StatusBadRequest, "test error")
		}
	})

	t.Run("HTML", func(t *testing.T) {
		for _, ep := range []string{"/e1", "/e2"} {
			req, err := http.NewRequest("GET", srv.URL+ep, nil)
			require.NoError(t, err)

			req.Header.Set("Accept", "text/html")
			rep, err := client.Do(req)
			require.NoError(t, err)
			require.Equal(t, 400, rep.StatusCode)
		}
	})

	t.Run("Plain", func(t *testing.T) {
		for _, ep := range []string{"/e1", "/e2"} {
			req, err := http.NewRequest("GET", srv.URL+ep, nil)
			require.NoError(t, err)

			req.Header.Set("Accept", "text/plain")
			rep, err := client.Do(req)
			require.NoError(t, err)
			require.Equal(t, 400, rep.StatusCode)
		}
	})
}

func TestError(t *testing.T) {
	tests := []struct {
		err      any
		expected string
	}{
		{nil, ""},
		{gimlet.ErrNoCSRFReferenceCookie, "no csrf reference cookie in request"},
		{gimlet.ErrorReply{Success: false, Err: "test error"}, "test error"},
		{"string error", "string error"},
		{42, "unhandled error response"},
	}

	for i, tc := range tests {
		rep := gimlet.Error(tc.err)
		require.False(t, rep.Success, "test %d: expected success to be false", i)
		require.Equal(t, tc.expected, rep.Err, "test %d: expected error message to match", i)
	}
}
