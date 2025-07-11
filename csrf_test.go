package gimlet_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet"
)

func TestDoubleCookie(t *testing.T) {
	makeCSRFTest := func(handler gimlet.CSRFTokenHandler) func(*testing.T) {
		return func(t *testing.T) {
			// Test both the DoubleCookie middleware and the SetDoubleCookieToken handler
			router := gin.New()

			// Add a route that sets the cookies
			router.GET("/protect", func(c *gin.Context) {
				if err := handler.SetDoubleCookieToken(c); err != nil {
					c.JSON(http.StatusInternalServerError, gimlet.Error(err))
				}
				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			// Add a route that requires CSRF protection
			router.POST("/action", gimlet.DoubleCookie(handler), func(c *gin.Context) {
				c.JSON(http.StatusCreated, gin.H{"success": true})
			})

			// Create a tls test server
			srv := httptest.NewTLSServer(router)
			defer srv.Close()

			// Create an https client with a cookie jar
			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			client := srv.Client()
			client.Jar = jar

			// Atttempt to make a request that is not CSRF protected
			t.Run("NoCSRFProtection", func(t *testing.T) {
				req, err := http.NewRequest(http.MethodPost, srv.URL+"/action", nil)
				require.NoError(t, err)

				// Ensure the request is Forbidden
				rep, err := client.Do(req)
				require.NoError(t, err)
				AssertErrorReply(t, rep, http.StatusForbidden, gimlet.ErrNoCSRFReferenceCookie.Error())
			})

			// Make a request that is CSRF protected
			t.Run("CSRFProtected", func(t *testing.T) {
				// First go to the protect endpoint to set the cookies
				req, err := http.NewRequest(http.MethodGet, srv.URL+"/protect", nil)
				require.NoError(t, err)

				rep, err := client.Do(req)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rep.StatusCode)

				// Send a valid request with the double cookie protection intact
				var cookieToken string
				for _, cookie := range rep.Cookies() {
					if cookie.Name == gimlet.CSRFCookie {
						cookieToken = cookie.Value
						break
					}
				}

				require.NotEmpty(t, cookieToken, "could not find cookie in response")

				// Now make a POST request to the action endpoint
				// This should succeed because we have the CSRF cookies set
				req, err = http.NewRequest(http.MethodPost, srv.URL+"/action", nil)
				require.NoError(t, err)

				req.Header.Set(gimlet.CSRFHeader, cookieToken)

				// Ensure the request is succeeds
				rep, err = client.Do(req)
				require.NoError(t, err)
				require.Equal(t, http.StatusCreated, rep.StatusCode)
			})

			// Make a request that has the reference cookie but not the header
			t.Run("MissingHeader", func(t *testing.T) {
				// First go to the protect endpoint to set the cookies
				req, err := http.NewRequest(http.MethodGet, srv.URL+"/protect", nil)
				require.NoError(t, err)

				rep, err := client.Do(req)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rep.StatusCode)

				// Now make a POST request to the action endpoint
				// This should succeed because we have the CSRF cookies set
				req, err = http.NewRequest(http.MethodPost, srv.URL+"/action", nil)
				require.NoError(t, err)

				// Ensure the request is Forbidden
				rep, err = client.Do(req)
				require.NoError(t, err)
				AssertErrorReply(t, rep, http.StatusForbidden, gimlet.ErrCSRFVerification.Error())
			})
		}
	}

	signedCSRF := &gimlet.SignedCSRFTokens{}
	signedCSRF.SetSecret(nil)
	t.Run("SignedCSRF", makeCSRFTest(signedCSRF))

	naiveCSRF := &gimlet.NaiveCSRFTokens{}
	t.Run("NaiveCSRF", makeCSRFTest(naiveCSRF))
}
