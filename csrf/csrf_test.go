package csrf_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	. "go.rtnl.ai/gimlet/csrf"
	"go.rtnl.ai/x/api"
)

func TestDoubleCookie(t *testing.T) {
	makeCSRFTest := func(handler TokenHandler) func(*testing.T) {
		return func(t *testing.T) {
			// Test both the DoubleCookie middleware and the SetDoubleCookieToken handler
			router := gin.New()

			// Add a route that sets the cookies
			router.GET("/protect", func(c *gin.Context) {
				if err := handler.SetDoubleCookieToken(c); err != nil {
					c.JSON(http.StatusInternalServerError, api.Error(err))
				}
				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			// Add a route that requires CSRF protection
			router.POST("/action", DoubleCookie(handler), func(c *gin.Context) {
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
				AssertErrorReply(t, rep, http.StatusForbidden, ErrNoCSRFReferenceCookie.Error())
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
					if cookie.Name == Cookie {
						cookieToken = cookie.Value
						break
					}
				}

				require.NotEmpty(t, cookieToken, "could not find cookie in response")

				// Now make a POST request to the action endpoint
				// This should succeed because we have the CSRF cookies set
				req, err = http.NewRequest(http.MethodPost, srv.URL+"/action", nil)
				require.NoError(t, err)

				req.Header.Set(Header, cookieToken)

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
				req, err = http.NewRequest(http.MethodPost, srv.URL+"/action", nil)
				require.NoError(t, err)

				// Ensure the request is Forbidden
				rep, err = client.Do(req)
				require.NoError(t, err)
				AssertErrorReply(t, rep, http.StatusForbidden, ErrCSRFVerification.Error())
			})

			// Make a request that has the header but not the reference cookie
			t.Run("MissingCookie", func(t *testing.T) {
				// Make a POST request to the action endpoint
				req, err := http.NewRequest(http.MethodPost, srv.URL+"/action", nil)
				require.NoError(t, err)

				req.Header.Set(Header, "fake-token")

				// Ensure the request is Forbidden
				rep, err := client.Do(req)
				require.NoError(t, err)
				AssertErrorReply(t, rep, http.StatusForbidden, ErrCSRFVerification.Error())
			})

			// Make a request where the cookie and header do not match
			t.Run("TokenVerifyFalse", func(t *testing.T) {
				// First go to the protect endpoint to set the cookies
				req, err := http.NewRequest(http.MethodGet, srv.URL+"/protect", nil)
				require.NoError(t, err)

				rep, err := client.Do(req)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rep.StatusCode)

				// Now make a POST request to the action endpoint
				req, err = http.NewRequest(http.MethodPost, srv.URL+"/action", nil)
				require.NoError(t, err)
				req.Header.Set(Header, "fake-token")

				// Ensure the request is Forbidden
				rep, err = client.Do(req)
				require.NoError(t, err)
				AssertErrorReply(t, rep, http.StatusForbidden, ErrCSRFVerification.Error())
			})

			// Make a request where the header is not URL escaped
			t.Run("HeaderNotEscaped", func(t *testing.T) {
				// First go to the protect endpoint to set the cookies
				req, err := http.NewRequest(http.MethodGet, srv.URL+"/protect", nil)
				require.NoError(t, err)

				rep, err := client.Do(req)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rep.StatusCode)

				// Now make a POST request to the action endpoint
				req, err = http.NewRequest(http.MethodPost, srv.URL+"/action", nil)
				require.NoError(t, err)
				req.Header.Set(Header, "no%escaping")

				// Ensure the request is Forbidden
				rep, err = client.Do(req)
				require.NoError(t, err)
				AssertErrorReply(t, rep, http.StatusBadRequest, ErrInvalidCSRFHeader.Error())
			})
		}
	}

	signedCSRF := &SignedCSRFTokens{}
	signedCSRF.SetSecret(nil)
	t.Run("SignedCSRF", makeCSRFTest(signedCSRF))

	naiveCSRF := &NaiveCSRFTokens{}
	t.Run("NaiveCSRF", makeCSRFTest(naiveCSRF))
}

func TestSetDoubleCookieToken(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "http://localhost:8000/test", nil)
		want := errors.New("test error")

		got := SetDoubleCookieToken(c, &TestGenerator{Err: want}, "", nil, time.Time{})
		require.ErrorIs(t, got, want, "expected error to match")
	})

	t.Run("Localhost", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "http://localhost:8000/test", nil)

		err := SetDoubleCookieToken(c, &TestGenerator{Token: "test"}, "/test", []string{"localhost"}, time.Now().Add(173*time.Minute))
		require.NoError(t, err)

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 2, "expected two cookies to be set")

		tokenRe := regexp.MustCompile(`csrf_token=test; Path=/test; Domain=localhost; Max-Age=(10438|10439|10440)`)
		refRe := regexp.MustCompile(`csrf_reference_token=test; Path=/test; Domain=localhost; Max-Age=(10438|10439|10440); HttpOnly`)

		for _, cookie := range cookies {
			require.True(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie))
		}
	})

	t.Run("Secure", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		err := SetDoubleCookieToken(c, &TestGenerator{Token: "test"}, "/test", []string{"example.com"}, time.Now().Add(173*time.Minute))
		require.NoError(t, err)

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 2, "expected two cookies to be set")

		tokenRe := regexp.MustCompile(`csrf_token=test; Path=/test; Domain=example.com; Max-Age=(10438|10439|10440); Secure`)
		refRe := regexp.MustCompile(`csrf_reference_token=test; Path=/test; Domain=example.com; Max-Age=(10438|10439|10440); HttpOnly; Secure`)

		for _, cookie := range cookies {
			require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})

	t.Run("RootPath", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		err := SetDoubleCookieToken(c, &TestGenerator{Token: "test"}, "", []string{"example.com"}, time.Now().Add(173*time.Minute))
		require.NoError(t, err)

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 2, "expected two cookies to be set")

		tokenRe := regexp.MustCompile(`csrf_token=test; Path=/; Domain=example.com; Max-Age=(10438|10439|10440); Secure`)
		refRe := regexp.MustCompile(`csrf_reference_token=test; Path=/; Domain=example.com; Max-Age=(10438|10439|10440); HttpOnly; Secure`)

		for _, cookie := range cookies {
			require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})

	t.Run("NoExpiration", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		err := SetDoubleCookieToken(c, &TestGenerator{Token: "test"}, "/test", []string{"example.com"}, time.Time{})
		require.NoError(t, err)

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 2, "expected two cookies to be set")

		tokenRe := regexp.MustCompile(`csrf_token=test; Path=/test; Domain=example.com; Max-Age=(3658|3659|3660); Secure`)
		refRe := regexp.MustCompile(`csrf_reference_token=test; Path=/test; Domain=example.com; Max-Age=(3658|3659|3660); HttpOnly; Secure`)

		for _, cookie := range cookies {
			require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})

	t.Run("MultipleDomains", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		err := SetDoubleCookieToken(c, &TestGenerator{Token: "test"}, "/", []string{"example.com", "example.io", "example.ai"}, time.Now().Add(time.Hour))
		require.NoError(t, err)

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 6, "expected four cookies to be set")

		tokenRe := regexp.MustCompile(`csrf_token=test; Path=/; Domain=(example.io|example.ai|example.com); Max-Age=(3658|3659|3660); Secure`)
		refRe := regexp.MustCompile(`csrf_reference_token=test; Path=/; Domain=(example.io|example.ai|example.com); Max-Age=(3658|3659|3660); HttpOnly; Secure`)

		for _, cookie := range cookies {
			require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})

	t.Run("Subdomains", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://auth.example.com/login", nil)

		err := SetDoubleCookieToken(c, &TestGenerator{Token: "test"}, "/", []string{"example.com", "auth.example.com", "db.example.com"}, time.Now().Add(time.Hour))
		require.NoError(t, err)

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 4, "expected six cookies to be set")

		tokenRe := regexp.MustCompile(`csrf_token=test; Path=/; Domain=(example.com|auth.example.com|db.example.com); Max-Age=(3658|3659|3660); Secure`)
		refRe := regexp.MustCompile(`csrf_reference_token=test; Path=/; Domain=example.com; Max-Age=(3658|3659|3660); HttpOnly; Secure`)

		for _, cookie := range cookies {
			require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})

	t.Run("MultipleSubdomains", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://auth.example.com/login", nil)

		err := SetDoubleCookieToken(c, &TestGenerator{Token: "test"}, "/", []string{"example.com", "auth.example.com", "db.example.com", "example.io", "auth.example.io", "db.example.io"}, time.Now().Add(time.Hour))
		require.NoError(t, err)

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 8, "expected six cookies to be set")

		tokenRe := regexp.MustCompile(`csrf_token=test; Path=/; Domain=(example.com|auth.example.com|db.example.com|example.io|auth.example.io|db.example.io); Max-Age=(3658|3659|3660); Secure`)
		refRe := regexp.MustCompile(`csrf_reference_token=test; Path=/; Domain=(example.com|example.io); Max-Age=(3658|3659|3660); HttpOnly; Secure`)

		for _, cookie := range cookies {
			require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})
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

type TestGenerator struct {
	Token string
	Err   error
}

func (g *TestGenerator) GenerateCSRFToken() (string, error) {
	if g.Err != nil {
		return "", g.Err
	}
	return g.Token, nil
}
