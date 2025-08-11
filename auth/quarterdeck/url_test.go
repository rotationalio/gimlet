package quarterdeck_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/auth/quarterdeck"
)

func TestLoginURL(t *testing.T) {
	t.Run("Location", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			login    string
			next     string
			expected string
		}{
			{
				"https://auth.rotational.app/login",
				"https://rotational.app/dashboard",
				"https://auth.rotational.app/login?next=https%3A%2F%2Frotational.app%2Fdashboard",
			},
			{
				"https://auth.rotational.app/login?apikey=12345",
				"https://rotational.app/dashboard",
				"https://auth.rotational.app/login?apikey=12345&next=https%3A%2F%2Frotational.app%2Fdashboard",
			},
			{
				"https://auth.rotational.app/login",
				"https://rotational.app/dashboard?color=blue",
				"https://auth.rotational.app/login?next=https%3A%2F%2Frotational.app%2Fdashboard%3Fcolor%3Dblue",
			},
			{
				"https://rotational.app/login",
				"https://rotational.app/dashboard",
				"/login?next=%2Fdashboard",
			},
			{
				"https://rotational.app/login?apikey=12345",
				"https://rotational.app/dashboard",
				"/login?apikey=12345&next=%2Fdashboard",
			},
			{
				"https://rotational.app/login",
				"https://rotational.app/dashboard?color=blue",
				"/login?next=%2Fdashboard%3Fcolor%3Dblue",
			},
			{
				"https://localhost:8000/login",
				"https://localhost:8888/dashboard",
				"https://localhost:8000/login?next=https%3A%2F%2Flocalhost%3A8888%2Fdashboard",
			},
			{
				"https://localhost:8000/login?apikey=12345",
				"https://localhost:8888/dashboard",
				"https://localhost:8000/login?apikey=12345&next=https%3A%2F%2Flocalhost%3A8888%2Fdashboard",
			},
			{
				"https://localhost:8000/login",
				"https://localhost:8888/dashboard?color=blue",
				"https://localhost:8000/login?next=https%3A%2F%2Flocalhost%3A8888%2Fdashboard%3Fcolor%3Dblue",
			},
			{
				"https://localhost:8000/login",
				"https://localhost:8000/dashboard",
				"/login?next=%2Fdashboard",
			},
			{
				"https://localhost:8000/login?apikey=12345",
				"https://localhost:8000/dashboard",
				"/login?apikey=12345&next=%2Fdashboard",
			},
			{
				"https://localhost:8000/login",
				"https://localhost:8000/dashboard?color=blue",
				"/login?next=%2Fdashboard%3Fcolor%3Dblue",
			},
		}

		for i, tc := range testCases {
			loginURL := &quarterdeck.LoginURL{}
			loginURL.Update(tc.login)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, tc.next, nil)

			actual := loginURL.Location(c)
			require.Equal(t, tc.expected, actual, "login URL location should match expected in test case %d", i)
		}
	})
}
