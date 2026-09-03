package csrf_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/csrf"
)

// Verify that a namespaced handler issues the expected cookie names and does
// not issue the legacy cookie names.
func TestNamespacedTokenHandler(t *testing.T) {
	handler, err := csrf.NewTokenHandlerWithNamespace(5*time.Minute, "", nil, nil, "endeavor")
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)
	require.NoError(t, handler.SetDoubleCookieToken(c))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 2)
	require.Contains(t, cookieNames(cookies), "endeavor_csrf_token")
	require.Contains(t, cookieNames(cookies), "endeavor_csrf_reference_token")
	require.NotContains(t, cookieNames(cookies), "csrf_token")
	require.NotContains(t, cookieNames(cookies), "csrf_reference_token")
}

// Verify that whitespace, capitalization, and unsafe namespace characters are
// normalized before cookie names are generated.
func TestNamespacedNamespaceNormalization(t *testing.T) {
	handler, err := csrf.NewTokenHandlerWithNamespace(5*time.Minute, "", nil, nil, " Endeavor.Service. ")
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)
	require.NoError(t, handler.SetDoubleCookieToken(c))

	names := cookieNames(w.Result().Cookies())
	require.Contains(t, names, "endeavor_service__csrf_token")
	require.Contains(t, names, "endeavor_service__csrf_reference_token")
}

// Verify that the secure constructor always creates a signed handler and
// rejects missing or insufficient secrets.
func TestNewSecureTokenHandler(t *testing.T) {
	handler, err := csrf.NewSecureTokenHandler(make([]byte, 32), "endeavor")
	require.NoError(t, err)
	_, ok := handler.(*csrf.SignedCSRFTokens)
	require.True(t, ok)

	names := handler.(csrf.Namespacer).Namespace()
	require.Equal(t, "__Host-endeavor_csrf_token", names.Cookie)
	require.Equal(t, "__Host-endeavor_csrf_reference_token", names.ReferenceCookie)
	require.Equal(t, "X-Endeavor-CSRF-Token", names.Header)
	require.Equal(t, "X-Endeavor-CSRF-Error", names.ErrorHeader)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	require.NoError(t, handler.SetDoubleCookieToken(c))
	require.ElementsMatch(t,
		[]string{"__Host-endeavor_csrf_token", "__Host-endeavor_csrf_reference_token"},
		cookieNames(w.Result().Cookies()),
	)

	handler, err = csrf.NewSecureTokenHandler([]byte("short"), "")
	require.ErrorIs(t, err, csrf.ErrShortSignedCSRFSecret)
	require.Nil(t, handler)

	handler, err = csrf.NewSecureTokenHandler(nil, "")
	require.ErrorIs(t, err, csrf.ErrNoSignedCSRFSecret)
	require.Nil(t, handler)
}

// Verify that independent handlers can share a host without overwriting each
// other's CSRF cookies or preventing valid requests.
func TestNamespacedCookiesDoNotCollide(t *testing.T) {
	router := gin.New()
	endeavor, err := csrf.NewTokenHandlerWithNamespace(5*time.Minute, "", nil, nil, "endeavor")
	require.NoError(t, err)
	quarterdeck, err := csrf.NewTokenHandlerWithNamespace(5*time.Minute, "", nil, nil, "quarterdeck")
	require.NoError(t, err)

	router.GET("/endeavor/token", func(c *gin.Context) {
		require.NoError(t, endeavor.SetDoubleCookieToken(c))
	})
	router.POST("/endeavor/action", csrf.DoubleCookie(endeavor), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})
	router.GET("/quarterdeck/token", func(c *gin.Context) {
		require.NoError(t, quarterdeck.SetDoubleCookieToken(c))
	})
	router.POST("/quarterdeck/action", csrf.DoubleCookie(quarterdeck), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})

	server := httptest.NewTLSServer(router)
	defer server.Close()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := server.Client()
	client.Jar = jar

	endeavorToken := issueToken(t, client, server.URL+"/endeavor/token", "endeavor_csrf_token")
	quarterdeckToken := issueToken(t, client, server.URL+"/quarterdeck/token", "quarterdeck_csrf_token")
	require.NotEqual(t, endeavorToken, quarterdeckToken)

	requirePostToken(t, client, server.URL+"/endeavor/action", "X-Endeavor-CSRF-Token", endeavorToken)
	requirePostToken(t, client, server.URL+"/quarterdeck/action", "X-Quarterdeck-CSRF-Token", quarterdeckToken)

	jarCookies := jarCookies(t, jar, server.URL)
	require.Contains(t, jarCookies, "endeavor_csrf_token")
	require.Contains(t, jarCookies, "endeavor_csrf_reference_token")
	require.Contains(t, jarCookies, "quarterdeck_csrf_token")
	require.Contains(t, jarCookies, "quarterdeck_csrf_reference_token")
}

// Verify that namespaced middleware rejects missing, mismatched, and malformed
// token requests.
func TestNamespacedMiddlewareRejectsInvalidRequests(t *testing.T) {
	handler, err := csrf.NewTokenHandlerWithNamespace(5*time.Minute, "", nil, nil, "endeavor")
	require.NoError(t, err)

	router := gin.New()
	router.GET("/token", func(c *gin.Context) {
		require.NoError(t, handler.SetDoubleCookieToken(c))
	})
	router.POST("/action", csrf.DoubleCookie(handler), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})
	server := httptest.NewTLSServer(router)
	defer server.Close()

	client := server.Client()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client.Jar = jar
	issueToken(t, client, server.URL+"/token", "endeavor_csrf_token")

	t.Run("MissingHeader", func(t *testing.T) {
		requirePostStatus(t, client, server.URL+"/action", "", "", http.StatusForbidden)
	})
	t.Run("MismatchedToken", func(t *testing.T) {
		requirePostStatus(t, client, server.URL+"/action", "X-Endeavor-CSRF-Token", "wrong", http.StatusForbidden)
	})
	t.Run("InvalidToken", func(t *testing.T) {
		requirePostStatus(t, client, server.URL+"/action", "X-Endeavor-CSRF-Token", "%<", http.StatusBadRequest)
	})
}

// Verify that a verifier implementing the optional namespacing interface causes
// the default middleware constructor to use its cookie and header names.
func TestDoubleCookieWithNamespacer(t *testing.T) {
	verifier := &namespacingVerifier{}
	router := gin.New()
	router.POST("/", csrf.DoubleCookie(verifier), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "endeavor_csrf_reference_token",
		Value: "token",
	})
	request.Header.Set("X-Endeavor-CSRF-Token", "token")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, 1, verifier.calls)
}

// Verify that safe HTTP methods bypass CSRF validation without invoking the
// token verifier.
func TestDoubleCookieSafeMethods(t *testing.T) {
	handler := &customVerifier{}
	router := gin.New()
	handlerFunc := csrf.DoubleCookie(handler)
	router.GET("/", handlerFunc, func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.HEAD("/", handlerFunc, func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.OPTIONS("/", handlerFunc, func(c *gin.Context) { c.Status(http.StatusNoContent) })
	server := httptest.NewServer(router)
	defer server.Close()

	client := server.Client()
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req, err := http.NewRequest(method, server.URL+"/", nil)
		require.NoError(t, err)
		rep, err := client.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, rep.StatusCode, method)
		require.NoError(t, rep.Body.Close())
	}
	require.Equal(t, 0, handler.calls)
}

// Verify that a custom verifier passed to the original middleware continues to
// use the legacy cookie and header names.
func TestDoubleCookieCustomVerifierKeepsLegacyNames(t *testing.T) {
	handler := &customVerifier{}
	router := gin.New()
	router.POST("/", csrf.DoubleCookie(handler), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	server := httptest.NewServer(router)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: csrf.ReferenceCookie, Value: "token"})
	req.Header.Set(csrf.Header, "token")
	rep, err := server.Client().Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, rep.StatusCode)
	require.NoError(t, rep.Body.Close())
	require.Equal(t, 1, handler.calls)
}

// Verify that a custom verifier can opt into namespaced request validation.
func TestDoubleCookieWithNamespaceCustomVerifier(t *testing.T) {
	handler := &customVerifier{}
	router := gin.New()
	router.POST("/", csrf.DoubleCookieWithNamespace(handler, "endeavor"), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	server := httptest.NewServer(router)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "endeavor_csrf_reference_token", Value: "token"})
	req.Header.Set("X-Endeavor-CSRF-Token", "token")
	rep, err := server.Client().Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, rep.StatusCode)
	require.NoError(t, rep.Body.Close())
	require.Equal(t, 1, handler.calls)
}

// Verify that a custom token generator can issue namespaced cookies explicitly.
func TestSetDoubleCookieTokenWithNamespace(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)

	err := csrf.SetDoubleCookieTokenWithNamespace(
		c, &TestGenerator{Token: "test"}, "/test", []string{"localhost"}, time.Time{}, "endeavor",
	)
	require.NoError(t, err)
	require.Contains(t, cookieNames(w.Result().Cookies()), "endeavor_csrf_token")
	require.Contains(t, cookieNames(w.Result().Cookies()), "endeavor_csrf_reference_token")
}

type customVerifier struct {
	calls int
}

func (v *customVerifier) VerifyCSRFToken(cookie, header string) (bool, error) {
	v.calls++
	return cookie == header, nil
}

type namespacingVerifier struct {
	calls int
}

func (v *namespacingVerifier) VerifyCSRFToken(cookie, header string) (bool, error) {
	v.calls++
	return cookie == header, nil
}

func (*namespacingVerifier) Namespace() csrf.Namespace {
	return csrf.Namespace{
		Cookie:          "endeavor_csrf_token",
		ReferenceCookie: "endeavor_csrf_reference_token",
		Header:          "X-Endeavor-CSRF-Token",
	}
}

func cookieNames(cookies []*http.Cookie) []string {
	names := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		names = append(names, cookie.Name)
	}
	return names
}

func issueToken(t *testing.T, client *http.Client, url, name string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	rep, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rep.StatusCode)
	defer rep.Body.Close()
	for _, cookie := range rep.Cookies() {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	t.Fatalf("could not find %s cookie", name)
	return ""
}

func requirePostToken(t *testing.T, client *http.Client, url, header, token string) {
	requirePostStatus(t, client, url, header, token, http.StatusCreated)
}

func requirePostStatus(t *testing.T, client *http.Client, url, header, token string, status int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, nil)
	require.NoError(t, err)
	if header != "" {
		req.Header.Set(header, token)
	}
	rep, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, rep.StatusCode)
	require.NoError(t, rep.Body.Close())
}

func jarCookies(t *testing.T, jar http.CookieJar, url string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, cookie := range jar.Cookies(mustURL(t, url)) {
		result[cookie.Name] = cookie.Value
	}
	return result
}

func mustURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	url, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	return url.URL
}
