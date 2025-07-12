package csrf_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/csrf"
)

func TestNewTokenHandler(t *testing.T) {
	t.Run("Secure", func(t *testing.T) {
		secret := make([]byte, 64)
		_, err := rand.Read(secret)
		require.NoError(t, err)

		handler, err := csrf.NewTokenHandler(5*time.Minute, "", []string{"example.com"}, secret)
		require.NoError(t, err)
		require.NotNil(t, handler)

		_, ok := handler.(*csrf.SignedCSRFTokens)
		require.True(t, ok, "Expected a SignedCSRFTokens handler, got %T", handler)
	})

	t.Run("Naive", func(t *testing.T) {
		handler, err := csrf.NewTokenHandler(5*time.Minute, "", []string{"example.com"}, nil)
		require.NoError(t, err)
		require.NotNil(t, handler)

		_, ok := handler.(*csrf.NaiveCSRFTokens)
		require.True(t, ok, "Expected a NaiveCSRFTokens handler, got %T", handler)
	})

	t.Run("Random", func(t *testing.T) {
		// Passing empty bytes will create a signed CSRF token handler with a random secret.
		handler, err := csrf.NewTokenHandler(5*time.Minute, "", []string{"example.com"}, []byte{})
		require.NoError(t, err)
		require.NotNil(t, handler)

		_, ok := handler.(*csrf.SignedCSRFTokens)
		require.True(t, ok, "Expected a SignedCSRFTokens handler, got %T", handler)
	})

	t.Run("Error", func(t *testing.T) {
		handler, err := csrf.NewTokenHandler(5*time.Minute, "", []string{"example.com"}, []byte("secret"))
		require.ErrorIs(t, err, csrf.ErrShortSignedCSRFSecret)
		require.Nil(t, handler)
	})
}

func TestSignedCSRFTokens(t *testing.T) {
	secret := make([]byte, 64)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	handler := &csrf.SignedCSRFTokens{}
	err = handler.SetSecret(secret)
	require.NoError(t, err)

	t.Run("Generate", func(t *testing.T) {
		// Should create unique tokens each time
		seen := make(map[string]struct{})
		for i := 0; i < 65; i++ {
			token, err := handler.GenerateCSRFToken()
			require.NoError(t, err)
			require.Regexp(t, `^[a-zA-Z0-9_-]{86}==$`, token)

			// Check uniqueness
			_, exists := seen[token]
			require.False(t, exists, "Token should be unique, but got a duplicate: %s", token)
			seen[token] = struct{}{}
		}
	})

	t.Run("Verify", func(t *testing.T) {
		token, err := handler.GenerateCSRFToken()
		require.NoError(t, err)

		valid, err := handler.VerifyCSRFToken(token, token)
		require.NoError(t, err)
		require.True(t, valid, "Expected token to be valid")
	})

	t.Run("Invalid", func(t *testing.T) {
		cookie, err := handler.GenerateCSRFToken()
		require.NoError(t, err)

		header, err := handler.GenerateCSRFToken()
		require.NoError(t, err)

		valid, err := handler.VerifyCSRFToken(cookie, header)
		require.NoError(t, err)
		require.False(t, valid, "Expected token to be invalid")
	})

	t.Run("Signing", func(t *testing.T) {
		expired, err := handler.GenerateCSRFToken()
		require.NoError(t, err)

		// Change the secret to simulate a signing failure
		err = handler.SetSecret(nil)
		require.NoError(t, err)

		valid, err := handler.VerifyCSRFToken(expired, expired)
		require.ErrorIs(t, err, csrf.ErrHMACVerificationFailed, "expected error for expired or mismatched tokens")
		require.False(t, valid, "expected expired or mismatched tokens to be invalid")
	})

	t.Run("Encoding", func(t *testing.T) {
		token, err := handler.GenerateCSRFToken()
		require.NoError(t, err)
		require.NotEmpty(t, token, "Expected token to be generated")

		tests := []struct {
			cookie string
			header string
			target error
		}{
			{"", "", csrf.ErrInvalidCSRFReference},
			{"", token, csrf.ErrInvalidCSRFReference},
			{token, "", csrf.ErrInvalidCSRFHeader},
			{"%<", token, csrf.ErrInvalidCSRFReference},
			{token, "%<", csrf.ErrInvalidCSRFHeader},
		}

		for i, tc := range tests {
			valid, err := handler.VerifyCSRFToken(tc.cookie, tc.header)
			require.ErrorIs(t, err, tc.target, "test %d: expected error for empty/non url encoded tokens", i)
			require.False(t, valid, "test %d: expected empty/non url encoded tokens to be invalid", i)
		}
	})
}

func TestNaiveCSRFTokens(t *testing.T) {
	handler := &csrf.NaiveCSRFTokens{}
	t.Run("Generate", func(t *testing.T) {
		// Should create unique tokens each time
		seen := make(map[string]struct{})
		for i := 0; i < 65; i++ {
			token, err := handler.GenerateCSRFToken()
			require.NoError(t, err)
			require.Regexp(t, `^[a-zA-Z0-9_-]{43}=$`, token)

			// Check uniqueness
			_, exists := seen[token]
			require.False(t, exists, "Token should be unique, but got a duplicate: %s", token)
			seen[token] = struct{}{}
		}
	})

	t.Run("Verify", func(t *testing.T) {
		token, err := handler.GenerateCSRFToken()
		require.NoError(t, err)

		valid, err := handler.VerifyCSRFToken(token, token)
		require.NoError(t, err)
		require.True(t, valid, "Expected token to be valid")
	})

	t.Run("Invalid", func(t *testing.T) {
		cookie, err := handler.GenerateCSRFToken()
		require.NoError(t, err)

		header, err := handler.GenerateCSRFToken()
		require.NoError(t, err)

		valid, err := handler.VerifyCSRFToken(cookie, header)
		require.NoError(t, err)
		require.False(t, valid, "Expected token to be invalid")
	})

	t.Run("Empty", func(t *testing.T) {
		token, err := handler.GenerateCSRFToken()
		require.NoError(t, err)
		require.NotEmpty(t, token, "Expected token to be generated")

		tests := []struct {
			cookie string
			header string
		}{
			{"", ""},
			{"", token},
			{token, ""},
		}

		for i, tc := range tests {
			valid, err := handler.VerifyCSRFToken(tc.cookie, tc.header)
			require.ErrorIs(t, err, csrf.ErrNaiveTokenFailed, "test %d: expected error for empty tokens", i)
			require.False(t, valid, "test %d: expected empty tokens to be invalid", i)
		}
	})
}

func TestHandlerSetDoubleCookieToken(t *testing.T) {
	secret := make([]byte, 64)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	t.Run("SingleDomain", func(t *testing.T) {
		mktest := func(handler csrf.CookieSetter) func(t *testing.T) {
			return func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

				err := handler.SetDoubleCookieToken(c)
				require.NoError(t, err)

				cookies := w.Header().Values("Set-Cookie")
				require.Len(t, cookies, 2, "expected two cookies to be set")

				tokenRe := regexp.MustCompile(`csrf_token=[a-zA-Z0-9_%-]+; Path=/; Domain=example.com; Max-Age=(359|360|361); Secure`)
				refRe := regexp.MustCompile(`csrf_reference_token=[a-zA-Z0-9_%-]+; Path=/; Domain=example.com; Max-Age=(359|360|361); HttpOnly; Secure`)

				for _, cookie := range cookies {
					require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
				}
			}
		}

		naive := &csrf.NaiveCSRFTokens{
			CookieTTL:    5 * time.Minute,
			CookieDomain: []string{"example.com"},
		}
		t.Run("NaiveCSRFTokens", mktest(naive))

		signed := &csrf.SignedCSRFTokens{
			CookieTTL:    5 * time.Minute,
			CookieDomain: []string{"example.com"},
		}
		err := signed.SetSecret(secret)
		require.NoError(t, err)

		t.Run("SignedCSRFTokens", mktest(signed))
	})

	t.Run("MultipleDomains", func(t *testing.T) {
		mktest := func(handler csrf.CookieSetter) func(t *testing.T) {
			return func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

				err := handler.SetDoubleCookieToken(c)
				require.NoError(t, err)

				cookies := w.Header().Values("Set-Cookie")
				require.Len(t, cookies, 6, "expected six cookies to be set")

				tokenRe := regexp.MustCompile(`csrf_token=[a-zA-Z0-9_%-]+; Path=/; Domain=(example.com|auth.example.com|db.example.com); Max-Age=(359|360|361); Secure`)
				refRe := regexp.MustCompile(`csrf_reference_token=[a-zA-Z0-9_%-]+; Path=/; Domain=(example.com|auth.example.com|db.example.com); Max-Age=(359|360|361); HttpOnly; Secure`)

				for _, cookie := range cookies {
					require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
				}
			}
		}

		naive := &csrf.NaiveCSRFTokens{
			CookieTTL:    5 * time.Minute,
			CookieDomain: []string{"example.com", "auth.example.com", "db.example.com"},
		}
		t.Run("NaiveCSRFTokens", mktest(naive))

		signed := &csrf.SignedCSRFTokens{
			CookieTTL:    5 * time.Minute,
			CookieDomain: []string{"example.com", "auth.example.com", "db.example.com"},
		}
		err := signed.SetSecret(secret)
		require.NoError(t, err)

		t.Run("SignedCSRFTokens", mktest(signed))
	})

	t.Run("NoDomain", func(t *testing.T) {
		mktest := func(handler csrf.CookieSetter) func(t *testing.T) {
			return func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

				err := handler.SetDoubleCookieToken(c)
				require.NoError(t, err)

				cookies := w.Header().Values("Set-Cookie")
				require.Len(t, cookies, 2, "expected two cookies to be set")

				tokenRe := regexp.MustCompile(`csrf_token=[a-zA-Z0-9_%-]+; Path=/; Max-Age=(359|360|361); Secure`)
				refRe := regexp.MustCompile(`csrf_reference_token=[a-zA-Z0-9_%-]+; Path=/; Max-Age=(359|360|361); HttpOnly; Secure`)

				for _, cookie := range cookies {
					require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
				}
			}
		}

		naive := &csrf.NaiveCSRFTokens{
			CookieTTL: 5 * time.Minute,
		}
		t.Run("NaiveCSRFTokens", mktest(naive))

		signed := &csrf.SignedCSRFTokens{
			CookieTTL: 5 * time.Minute,
		}
		err := signed.SetSecret(secret)
		require.NoError(t, err)

		t.Run("SignedCSRFTokens", mktest(signed))
	})

	t.Run("NoCookieTTL", func(t *testing.T) {
		mktest := func(handler csrf.CookieSetter) func(t *testing.T) {
			return func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

				err := handler.SetDoubleCookieToken(c)
				require.NoError(t, err)

				cookies := w.Header().Values("Set-Cookie")
				require.Len(t, cookies, 2, "expected two cookies to be set")

				tokenRe := regexp.MustCompile(`csrf_token=[a-zA-Z0-9_%-]+; Path=/; Max-Age=(3659|3660|3661); Secure`)
				refRe := regexp.MustCompile(`csrf_reference_token=[a-zA-Z0-9_%-]+; Path=/; Max-Age=(3659|3660|3661); HttpOnly; Secure`)

				for _, cookie := range cookies {
					require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
				}
			}
		}

		naive := &csrf.NaiveCSRFTokens{}
		t.Run("NaiveCSRFTokens", mktest(naive))

		signed := &csrf.SignedCSRFTokens{}
		err := signed.SetSecret(secret)
		require.NoError(t, err)

		t.Run("SignedCSRFTokens", mktest(signed))
	})

	t.Run("WithPath", func(t *testing.T) {
		mktest := func(handler csrf.CookieSetter) func(t *testing.T) {
			return func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

				err := handler.SetDoubleCookieToken(c)
				require.NoError(t, err)

				cookies := w.Header().Values("Set-Cookie")
				require.Len(t, cookies, 2, "expected two cookies to be set")

				tokenRe := regexp.MustCompile(`csrf_token=[a-zA-Z0-9_%-]+; Path=/test; Max-Age=(359|360|361); Secure`)
				refRe := regexp.MustCompile(`csrf_reference_token=[a-zA-Z0-9_%-]+; Path=/test; Max-Age=(359|360|361); HttpOnly; Secure`)

				for _, cookie := range cookies {
					require.Truef(t, tokenRe.MatchString(cookie) || refRe.MatchString(cookie), "%q does not match regular expressions", cookie)
				}
			}
		}

		naive := &csrf.NaiveCSRFTokens{
			CookieTTL:  5 * time.Minute,
			CookiePath: "/test",
		}
		t.Run("NaiveCSRFTokens", mktest(naive))

		signed := &csrf.SignedCSRFTokens{
			CookieTTL:  5 * time.Minute,
			CookiePath: "/test",
		}
		err := signed.SetSecret(secret)
		require.NoError(t, err)

		t.Run("SignedCSRFTokens", mktest(signed))
	})
}
