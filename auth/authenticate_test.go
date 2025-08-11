package auth_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/gimlet/auth"
	"go.rtnl.ai/ulid"
)

func TestAuthenticate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock := &MockVerifier{}
	authenticate, err := auth.Authenticate(mock)
	require.NoError(t, err, "should create authenticate middleware without error")

	t.Run("NoAccessToken", func(t *testing.T) {
		defer mock.Reset()

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

		authenticate(c)
		require.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 Unauthorized when no access token is provided")
		mock.AssertNotCalled(t, "Verify")
	})

	t.Run("InvalidAccessToken", func(t *testing.T) {
		defer mock.Reset()
		mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
			return nil, errors.New("token signned with invalid keys")
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Authorization", "Bearer notauthorizedtobehere")

		authenticate(c)
		require.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 Unauthorized when no access token is provided")
		mock.AssertCalled(t, "Verify", 1)

		claims, err := auth.GetClaims(c)
		require.ErrorIs(t, err, auth.ErrNoAuthorization, "should return ErrNoAuthorization when access token is invalid")
		require.Nil(t, claims, "should not set claims in context when access token is invalid")

		accessToken, exists := gimlet.Get(c, gimlet.KeyAccessToken)
		require.False(t, exists, "should not set access token in context when access token is invalid")
		require.Empty(t, accessToken, "should not set access token in context when access token is invalid")
	})

	t.Run("ValidAccessToken", func(t *testing.T) {
		defer mock.Reset()
		mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
			return &auth.Claims{Name: "testuser"}, nil
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Authorization", "Bearer guywhoworkshere")

		authenticate(c)
		require.Equal(t, http.StatusOK, w.Code, "should return 200 OK when access token is valid")
		mock.AssertCalled(t, "Verify", 1)

		claims, err := auth.GetClaims(c)
		require.NoError(t, err, "should retrieve claims from context")
		require.Equal(t, "testuser", claims.Name, "should match claims name from access token")

		accessToken, exists := gimlet.Get(c, gimlet.KeyAccessToken)
		require.True(t, exists, "should set access token in context")
		require.Equal(t, "guywhoworkshere", accessToken, "should match access token from header")
	})
}

func TestAuthenticateWithUnauthenticator(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock := &MockUnauthenticator{}
	authenticate, err := auth.Authenticate(mock)
	require.NoError(t, err, "should create authenticate middleware without error")

	t.Run("NoAccessToken", func(t *testing.T) {
		defer mock.Reset()
		mock.OnNotAuthorized = func(c *gin.Context) error {
			c.Redirect(http.StatusSeeOther, "/login")
			return nil
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

		authenticate(c)
		require.Equal(t, http.StatusSeeOther, w.Code, "should return 303 See Other when no access token is provided")
		require.Equal(t, "/login", w.Result().Header.Get("Location"), "should redirect to /login when not authorized")
		mock.AssertNotCalled(t, "Verify")
		mock.AssertCalled(t, "NotAuthorized", 1)

		claims, err := auth.GetClaims(c)
		require.ErrorIs(t, err, auth.ErrNoAuthorization, "should return ErrNoAuthorization when access token is invalid")
		require.Nil(t, claims, "should not set claims in context when access token is invalid")

		accessToken, exists := gimlet.Get(c, gimlet.KeyAccessToken)
		require.False(t, exists, "should not set access token in context when access token is invalid")
		require.Empty(t, accessToken, "should not set access token in context when access token is invalid")
	})

	t.Run("InvalidAccessToken", func(t *testing.T) {
		defer mock.Reset()
		mock.OnNotAuthorized = func(c *gin.Context) error {
			c.Redirect(http.StatusSeeOther, "/login")
			return nil
		}
		mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
			return nil, errors.New("token signed with invalid keys")
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Authorization", "Bearer notauthorizedtobehere")

		authenticate(c)
		require.Equal(t, http.StatusSeeOther, w.Code, "should return 303 See Other when no access token is provided")
		require.Equal(t, "/login", w.Result().Header.Get("Location"), "should redirect to /login when not authorized")
		mock.AssertCalled(t, "Verify", 1)
		mock.AssertCalled(t, "NotAuthorized", 1)

		claims, err := auth.GetClaims(c)
		require.ErrorIs(t, err, auth.ErrNoAuthorization, "should return ErrNoAuthorization when access token is invalid")
		require.Nil(t, claims, "should not set claims in context when access token is invalid")

		accessToken, exists := gimlet.Get(c, gimlet.KeyAccessToken)
		require.False(t, exists, "should not set access token in context when access token is invalid")
		require.Empty(t, accessToken, "should not set access token in context when access token is invalid")

	})

	t.Run("HandlerError", func(t *testing.T) {
		defer mock.Reset()
		mock.OnNotAuthorized = func(c *gin.Context) error {
			return errors.New("something went wrong")
		}
		mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
			return nil, errors.New("token signed with invalid keys")
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Authorization", "Bearer notauthorizedtobehere")

		authenticate(c)
		require.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 Unauthorized when no access token is provided")
		require.Equal(t, "", w.Result().Header.Get("Location"), "no location header should be set when handler returns an error")
		mock.AssertCalled(t, "Verify", 1)
		mock.AssertCalled(t, "NotAuthorized", 1)

		claims, err := auth.GetClaims(c)
		require.ErrorIs(t, err, auth.ErrNoAuthorization, "should return ErrNoAuthorization when access token is invalid")
		require.Nil(t, claims, "should not set claims in context when access token is invalid")

		accessToken, exists := gimlet.Get(c, gimlet.KeyAccessToken)
		require.False(t, exists, "should not set access token in context when access token is invalid")
		require.Empty(t, accessToken, "should not set access token in context when access token is invalid")
	})

	t.Run("Authenticated", func(t *testing.T) {
		defer mock.Reset()
		mock.OnNotAuthorized = func(c *gin.Context) error {
			c.Redirect(http.StatusSeeOther, "/login")
			return nil
		}
		mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
			return &auth.Claims{Name: "testuser"}, nil
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Authorization", "Bearer notauthorizedtobehere")

		authenticate(c)
		require.Equal(t, http.StatusOK, w.Code, "should return 200 OK when access token is valid")
		mock.AssertCalled(t, "Verify", 1)
		mock.AssertNotCalled(t, "NotAuthorized")
	})
}

func TestAuthenticateWithReauthenticator(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock := &MockReauthenticator{}
	authenticate, err := auth.Authenticate(mock)
	require.NoError(t, err, "should create authenticate middleware without error")

	t.Run("NoAccessToken", func(t *testing.T) {
		t.Run("NoRefreshToken", func(t *testing.T) {
			defer mock.Reset()
			mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
				return nil, errors.New("not authorized")
			}
			mock.OnRefresh = func(accessToken, refreshToken string) (*auth.Claims, error) {
				return nil, errors.New("not allowed")
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

			authenticate(c)

			require.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 Unauthorized when no access token is provided")
			mock.AssertNotCalled(t, "Verify")
			mock.AssertNotCalled(t, "Refresh")
		})

		t.Run("WithRefreshToken", func(t *testing.T) {
			defer mock.Reset()
			mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
				return nil, errors.New("not authorized")
			}
			mock.OnRefresh = func(accessToken, refreshToken string) (*auth.Claims, error) {
				return nil, errors.New("not allowed")
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			c.Request.AddCookie(&http.Cookie{Name: auth.RefreshTokenCookie, Value: "spoof-foo"})

			authenticate(c)

			require.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 Unauthorized when no access token is provided")
			mock.AssertNotCalled(t, "Verify")
			mock.AssertNotCalled(t, "Refresh")
		})
	})

	t.Run("WithAccessToken", func(t *testing.T) {
		t.Run("NoRefreshToken", func(t *testing.T) {
			defer mock.Reset()
			mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
				return nil, errors.New("not authorized")
			}
			mock.OnRefresh = func(accessToken, refreshToken string) (*auth.Claims, error) {
				if accessToken != "expired-access-token" || refreshToken != "" {
					panic("unexpected access or refresh token")
				}
				return nil, errors.New("not allowed")
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			c.Request.Header.Set("Authorization", "Bearer expired-access-token")

			authenticate(c)

			require.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 Unauthorized when no access token is provided")
			mock.AssertCalled(t, "Verify", 1)
			mock.AssertNotCalled(t, "Refresh")
		})

		t.Run("WithRefreshToken", func(t *testing.T) {
			t.Run("Success", func(t *testing.T) {
				defer mock.Reset()
				mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
					return nil, errors.New("not authorized")
				}
				mock.OnRefresh = func(accessToken, refreshToken string) (*auth.Claims, error) {
					if accessToken != "expired-access-token" || refreshToken != "valid-refresh-token" {
						panic("unexpected access or refresh token")
					}
					return &auth.Claims{Name: "testuser"}, nil
				}

				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
				c.Request.AddCookie(&http.Cookie{Name: auth.RefreshTokenCookie, Value: "valid-refresh-token"})
				c.Request.Header.Set("Authorization", "Bearer expired-access-token")

				authenticate(c)

				require.Equal(t, http.StatusOK, w.Code, "should return 200 OK when refresh token is valid")
				mock.AssertCalled(t, "Verify", 1)
				mock.AssertCalled(t, "Refresh", 1)

				claims, err := auth.GetClaims(c)
				require.NoError(t, err, "should retrieve claims from context")
				require.Equal(t, "testuser", claims.Name, "should match claims name from access token")

				accessToken, exists := gimlet.Get(c, gimlet.KeyAccessToken)
				require.True(t, exists, "should set access token in context")
				require.Equal(t, "expired-access-token", accessToken, "access token should match the one provided")
			})

			t.Run("Error", func(t *testing.T) {
				defer mock.Reset()
				mock.OnVerify = func(accessToken string) (*auth.Claims, error) {
					return nil, errors.New("not authorized")
				}
				mock.OnRefresh = func(accessToken, refreshToken string) (*auth.Claims, error) {
					if accessToken != "expired-access-token" || refreshToken != "spoof-foo" {
						panic("unexpected access or refresh token")
					}
					return nil, errors.New("not allowed")
				}

				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
				c.Request.AddCookie(&http.Cookie{Name: auth.RefreshTokenCookie, Value: "spoof-foo"})
				c.Request.Header.Set("Authorization", "Bearer expired-access-token")

				authenticate(c)

				require.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 Unauthorized when no access token is provided")
				mock.AssertCalled(t, "Verify", 1)
				mock.AssertCalled(t, "Refresh", 1)
			})
		})
	})
}

func TestGetAccessToken(t *testing.T) {
	mkctx := func(header, cookie string) *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

		if header != "" {
			c.Request.Header.Set("Authorization", header)
		}

		if cookie != "" {
			c.Request.AddCookie(&http.Cookie{Name: auth.AccessTokenCookie, Value: cookie})
		}
		return c
	}

	t.Run("FromHeader", func(t *testing.T) {
		c := mkctx("Bearer "+accessToken, "")
		token, err := auth.GetAccessToken(c)
		require.NoError(t, err, "should retrieve access token from header")
		require.Equal(t, accessToken, token, "should match access token from header")
	})

	t.Run("FromCookie", func(t *testing.T) {
		c := mkctx("", accessToken)
		token, err := auth.GetAccessToken(c)
		require.NoError(t, err, "should retrieve access token from cookie")
		require.Equal(t, accessToken, token, "should match access token from cookie")
	})

	t.Run("HeaderTakesPrecedence", func(t *testing.T) {
		c := mkctx("Bearer "+accessToken, "different-cookie-value")
		token, err := auth.GetAccessToken(c)
		require.NoError(t, err, "should retrieve access token from header")
		require.Equal(t, accessToken, token, "should match access token from header")
	})

	t.Run("CannotParseBearer", func(t *testing.T) {
		c := mkctx("InvalidBearerToken", "")
		token, err := auth.GetAccessToken(c)
		require.Error(t, err, "should return error for invalid bearer token")
		require.Empty(t, token, "should not return token for invalid bearer token")
	})

	t.Run("NotFound", func(t *testing.T) {
		c := mkctx("", "")
		token, err := auth.GetAccessToken(c)
		require.Error(t, err, "should return error for missing token")
		require.Empty(t, token, "should not return token for missing token")
	})
}

func TestGetRefreshToken(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	// Should return an error when no refresh token is set
	cookie, err := auth.GetRefreshToken(c)
	require.ErrorIs(t, err, auth.ErrNoRefreshToken, "should return error when no refresh token is set")
	require.Empty(t, cookie, "should not return a token when no refresh token is set")

	c.Request.AddCookie(&http.Cookie{Name: auth.RefreshTokenCookie, Value: refreshToken})
	cookie, err = auth.GetRefreshToken(c)
	require.NoError(t, err, "should retrieve refresh token from cookie")
	require.Equal(t, refreshToken, cookie, "should match refresh token from cookie")
}

func TestSetAuthCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	accessToken, refreshToken, err := createTokens(&auth.Claims{Name: "Test User"})
	require.NoError(t, err, "should create tokens successfully")

	mkctx := func() (*gin.Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		return c, w
	}

	t.Run("Secure", func(t *testing.T) {
		c, w := mkctx()
		err := auth.SetAuthCookies(c, accessToken, refreshToken, "example.com", "auth.example.com")
		require.NoError(t, err, "should set cookies successfully")

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 4, "expected four cookies to be set")

		accessRE := regexp.MustCompile(`access_token=[a-zA-Z0-9-_.]+; Path=/; Domain=(example.com|auth.example.com); Max-Age=(3599|3600|3601); HttpOnly; Secure`)
		refreshRE := regexp.MustCompile(`refresh_token=[a-zA-Z0-9-_.]+; Path=/; Domain=(example.com|auth.example.com); Max-Age=(7199|7200|7201); Secure`)

		for _, cookie := range cookies {
			require.Truef(t, accessRE.MatchString(cookie) || refreshRE.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})

	t.Run("NonSecure", func(t *testing.T) {
		c, w := mkctx()
		err := auth.SetAuthCookies(c, accessToken, refreshToken, "localhost", "auth.local")
		require.NoError(t, err, "should set cookies successfully")

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 4, "expected four cookies to be set")

		accessRE := regexp.MustCompile(`access_token=[a-zA-Z0-9-_.]+; Path=/; Domain=(localhost|auth.local); Max-Age=(3599|3600|3601); HttpOnly`)
		refreshRE := regexp.MustCompile(`refresh_token=[a-zA-Z0-9-_.]+; Path=/; Domain=(localhost|auth.local); Max-Age=(7199|7200|7201)`)

		for _, cookie := range cookies {
			require.Truef(t, accessRE.MatchString(cookie) || refreshRE.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})
}

func TestClearAuthCookies(t *testing.T) {
	mkctx := func() (*gin.Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		return c, w
	}

	t.Run("Secure", func(t *testing.T) {
		c, w := mkctx()
		auth.ClearAuthCookies(c, "example.com", "auth.example.com")

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 4, "expected four cookies to be cleared")

		accessRE := regexp.MustCompile(`access_token=; Path=/; Domain=(example.com|auth.example.com); Max-Age=0; HttpOnly; Secure`)
		refreshRE := regexp.MustCompile(`refresh_token=; Path=/; Domain=(example.com|auth.example.com); Max-Age=0; Secure`)

		for _, cookie := range cookies {
			require.Truef(t, accessRE.MatchString(cookie) || refreshRE.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})

	t.Run("NonSecure", func(t *testing.T) {
		c, w := mkctx()
		auth.ClearAuthCookies(c, "localhost", "auth.local")

		cookies := w.Header().Values("Set-Cookie")
		require.Len(t, cookies, 4, "expected four cookies to be cleared")

		accessRE := regexp.MustCompile(`access_token=; Path=/; Domain=(localhost|auth.local); Max-Age=0; HttpOnly`)
		refreshRE := regexp.MustCompile(`refresh_token=; Path=/; Domain=(localhost|auth.local); Max-Age=0`)

		for _, cookie := range cookies {
			require.Truef(t, accessRE.MatchString(cookie) || refreshRE.MatchString(cookie), "%q does not match regular expressions", cookie)
		}
	})
}

//===========================================================================
// Helper Function to Generate Access and Refresh Tokens
//===========================================================================

var (
	initAuth sync.Once
	pubKey   ed25519.PublicKey
	privKey  ed25519.PrivateKey
)

func createTokens(claims *auth.Claims) (accessToken string, refreshToken string, err error) {
	initAuth.Do(func() {
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
	})

	if err != nil {
		return "", "", err
	}

	if len(privKey) == 0 || len(pubKey) == 0 {
		return "", "", errors.New("no keys available")
	}

	atkn := createAccessToken(claims)
	rtkn := createRefreshToken(atkn)

	atkn.Header["kid"] = "test-key"
	rtkn.Header["kid"] = "test-key"

	if accessToken, err = atkn.SignedString(&privKey); err != nil {
		return "", "", err
	}

	if refreshToken, err = rtkn.SignedString(&privKey); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func createAccessToken(claims *auth.Claims) *jwt.Token {
	now := time.Now()
	sub := claims.Subject
	aud := claims.Audience

	claims.RegisteredClaims = jwt.RegisteredClaims{
		ID:        ulid.MakeSecure().String(),
		Subject:   sub,
		Audience:  aud,
		Issuer:    "test.dev",
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
	}

	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
}

func createRefreshToken(accessToken *jwt.Token) *jwt.Token {
	claims := accessToken.Claims.(*auth.Claims)

	refreshClaims := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        claims.ID,
			Subject:   claims.Subject,
			Audience:  jwt.ClaimStrings{"test.dev/reauthenticate"},
			Issuer:    claims.Issuer,
			IssuedAt:  claims.IssuedAt,
			NotBefore: jwt.NewNumericDate(claims.ExpiresAt.Add(-15 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(claims.IssuedAt.Add(2 * time.Hour)),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, refreshClaims)
}

//===========================================================================
// Mock Authenticator/Reauthenticator for Testing
//===========================================================================

type Mock struct {
	calls map[string]int
}

func (m *Mock) Reset() {
	m.calls = nil
}

func (m *Mock) incr(method string) {
	if m.calls == nil {
		m.calls = make(map[string]int)
	}
	m.calls[method]++
}

func (m *Mock) AssertCalled(t *testing.T, method string, calls int) {
	require.Contains(t, m.calls, method, "method %s was not called", method)
	require.Equal(t, calls, m.calls[method], "method %s was called %d times, expected %d", method, m.calls[method], calls)
}

func (m *Mock) AssertNotCalled(t *testing.T, method string) {
	require.NotContains(t, m.calls, method, "method %s should not have been called", method)
}

type MockVerifier struct {
	Mock
	OnVerify func(accessToken string) (claims *auth.Claims, err error)
}

func (m *MockVerifier) Reset() {
	m.Mock.Reset()
	m.OnVerify = nil
}

func (m *MockVerifier) Verify(accessToken string) (claims *auth.Claims, err error) {
	m.incr("Verify")
	if m.OnVerify != nil {
		return m.OnVerify(accessToken)
	}
	panic("no Verify() callback defined")
}

type MockReauthenticator struct {
	MockVerifier
	OnRefresh func(accessToken, refreshToken string) (claims *auth.Claims, err error)
}

func (m *MockReauthenticator) Reset() {
	m.MockVerifier.Reset()
	m.OnRefresh = nil
}

func (m *MockReauthenticator) Refresh(accessToken, refreshToken string) (claims *auth.Claims, err error) {
	m.incr("Refresh")
	if m.OnRefresh != nil {
		return m.OnRefresh(accessToken, refreshToken)
	}
	panic("no Refresh() callback defined")
}

type MockUnauthenticator struct {
	MockVerifier
	OnNotAuthorized func(c *gin.Context) error
}

func (m *MockUnauthenticator) Reset() {
	m.MockVerifier.Reset()
	m.OnNotAuthorized = nil
}

func (m *MockUnauthenticator) NotAuthorized(c *gin.Context) error {
	m.incr("NotAuthorized")
	if m.OnNotAuthorized != nil {
		return m.OnNotAuthorized(c)
	}
	panic("no NotAuthorized() callback defined")
}
