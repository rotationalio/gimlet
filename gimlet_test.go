package gimlet_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/x/api"
)

func TestSetCookie(t *testing.T) {
	t.Run("Localhost", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "http://localhost:8000/test", nil)

		gimlet.SetCookie(c, "foo", "bar", "/test", "localhost", time.Now().Add(173*time.Minute), true)
		require.Regexp(t, `foo=bar; Path=/test; Domain=localhost; Max-Age=(10438|10439|10440); HttpOnly`, w.Header().Get("Set-Cookie"))
	})

	t.Run("Secure", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://example.colm/test", nil)

		gimlet.SetCookie(c, "foo", "bar", "/test", "example.com", time.Now().Add(173*time.Minute), true)
		require.Regexp(t, `foo=bar; Path=/test; Domain=example.com; Max-Age=(10438|10439|10440); HttpOnly; Secure`, w.Header().Get("Set-Cookie"))
	})

	t.Run("RootPath", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		gimlet.SetCookie(c, "foo", "bar", "", "example.com", time.Now().Add(173*time.Minute), true)
		require.Regexp(t, `foo=bar; Path=/; Domain=example.com; Max-Age=(10438|10439|10440); HttpOnly; Secure`, w.Header().Get("Set-Cookie"))
	})

	t.Run("NoExpiration", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		gimlet.SetCookie(c, "foo", "bar", "/test", "example.com", time.Time{}, true)
		require.Regexp(t, `foo=bar; Path=/test; Domain=example.com; Max-Age=(3658|3659|3660); HttpOnly; Secure`, w.Header().Get("Set-Cookie"))
	})
}

func TestClearCookie(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

	gimlet.ClearCookie(c, "foo", "/test", "example.com", true)
	require.Regexp(t, `foo=; Path=/test; Domain=example.com; Max-Age=0; HttpOnly; Secure`, w.Header().Get("Set-Cookie"))
}

func TestIsLocalhost(t *testing.T) {
	testCases := []struct {
		domain string
		assert require.BoolAssertionFunc
	}{
		{
			"localhost",
			require.True,
		},
		{
			"endeavor.local",
			require.True,
		},
		{
			"honu.local",
			require.True,
		},
		{
			"quarterdeck",
			require.False,
		},
		{
			"rotational.app",
			require.False,
		},
		{
			"auth.rotational.app",
			require.False,
		},
		{
			"quarterdeck.local.example.io",
			require.False,
		},
	}

	for i, tc := range testCases {
		tc.assert(t, gimlet.IsLocalhost(tc.domain), "test case %d failed", i)
	}
}

//===========================================================================
// Test Helpers
//===========================================================================

func AssertErrorReply(t *testing.T, rep *http.Response, expectedStatus int, expectedError string) {
	defer rep.Body.Close()

	require.Equal(t, expectedStatus, rep.StatusCode, "expected status code to match")

	data := &api.Reply{}
	err := json.NewDecoder(rep.Body).Decode(data)
	require.NoError(t, err, "could not parse response body")

	require.False(t, data.Success, "expected success to be false")
	require.Equal(t, expectedError, data.Error, "expected error message to match")
}

func ReadJSON(rep *http.Response) (*api.Reply, error) {
	defer rep.Body.Close()
	data := &api.Reply{}
	if err := json.NewDecoder(rep.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}
