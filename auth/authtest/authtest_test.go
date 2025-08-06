package authtest_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/auth"
	"go.rtnl.ai/gimlet/auth/authtest"
	"go.rtnl.ai/ulid"
)

func TestServer(t *testing.T) {
	// Create a new testing server for the tests in this function.
	srv := authtest.New(t)
	client := srv.Client()
	url := srv.URL()

	t.Run("JWKS", func(t *testing.T) {
		resp, err := client.Get(url.String() + "/.well-known/jwks.json")
		require.NoError(t, err, "could not fetch JWKS")
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code")

		keys := jose.JSONWebKeySet{}
		err = json.NewDecoder(resp.Body).Decode(&keys)
		require.NoError(t, err, "could not decode JWKS response")

		require.NotEmpty(t, keys.Keys, "JWKS should not be empty")
		require.Len(t, keys.Keys, 1, "JWKS should contain exactly one key")

		require.NotEmpty(t, resp.Header.Get("Cache-Control"), "Cache-Control header should be set")
		require.NotEmpty(t, resp.Header.Get("Expires"), "Expires header should be set")
		require.NotEmpty(t, resp.Header.Get("ETag"), "ETag header should be set")
		require.NotEmpty(t, resp.Header.Get("Content-Type"), "Content-Type header should be set")
	})

	t.Run("OpenIDConfig", func(t *testing.T) {
		resp, err := client.Get(url.String() + "/.well-known/openid-configuration")
		require.NoError(t, err, "could not fetch OpenID configuration")
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code")

		config := make(map[string]interface{})
		err = json.NewDecoder(resp.Body).Decode(&config)
		require.NoError(t, err, "could not decode OpenID configuration response")

		require.NotEmpty(t, config["issuer"], "Issuer should not be empty")
		require.NotEmpty(t, config["jwks_uri"], "JWKS URI should not be empty")

		require.NotEmpty(t, resp.Header.Get("Cache-Control"), "Cache-Control header should be set")
		require.NotEmpty(t, resp.Header.Get("Expires"), "Expires header should be set")
		require.NotEmpty(t, resp.Header.Get("ETag"), "ETag header should be set")
		require.NotEmpty(t, resp.Header.Get("Content-Type"), "Content-Type header should be set")
	})

	t.Run("Authentication", func(t *testing.T) {
		claims := &auth.Claims{
			Name:  "John Doe",
			Email: "jdoe@example.com",
		}
		claims.SetSubjectID(auth.SubjectUser, ulid.Make())

		token, err := srv.CreateAccessToken(claims)
		require.NoError(t, err, "could not create access token")

		_, err = srv.Verify(token)
		require.NoError(t, err, "could not verify access token")
	})
}
