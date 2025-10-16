package quarterdeck_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/auth"
	"go.rtnl.ai/gimlet/auth/authtest"
	"go.rtnl.ai/gimlet/auth/quarterdeck"
	"go.rtnl.ai/ulid"
)

func TestQuarterdeck(t *testing.T) {
	srv := authtest.New(t)
	client := srv.Client()

	qd, err := quarterdeck.New(srv.ConfigURL(), authtest.Audience,
		quarterdeck.WithClient(client),
		quarterdeck.WithIssuer(authtest.Issuer),
		quarterdeck.WithSigningMethods([]string{authtest.SigningMethod().Alg()}),
	)
	require.NoError(t, err, "could not create Quarterdeck instance")

	claims := &auth.Claims{
		Name:  "John Doe",
		Email: "jdoe@example.com",
	}
	claims.SetSubjectID(auth.SubjectUser, ulid.Make())

	accessToken, err := srv.CreateAccessToken(claims)
	require.NoError(t, err, "could not create access token")

	verified, err := qd.Verify(accessToken)
	require.NoError(t, err, "could not verify access token")
	require.NotNil(t, verified, "verified claims should not be nil")
	require.Equal(t, claims.Name, verified.Name, "name should match")
	require.Equal(t, claims.Email, verified.Email, "email should match")

	refreshToken, err := srv.CreateRefreshToken(claims)
	require.NoError(t, err, "could not create refresh token")

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

	refreshed, err := qd.Refresh(auth.Tokens{
		Context:      c,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})

	require.NoError(t, err, "could not refresh authentication")
	require.NotNil(t, refreshed, "refreshed tokens should not be nil")
	require.NotNil(t, refreshed.Claims, "refreshed claims should not be nil")
	require.NotZero(t, refreshed.AccessToken, "new access token should not be empty")
	require.NotZero(t, refreshed.RefreshToken, "new refresh token should not be empty")
	require.Equal(t, claims.Name, refreshed.Claims.Name, "new name should match old one")
	require.Equal(t, claims.Email, refreshed.Claims.Email, "new email should match old one")

	newVerified, err := qd.Verify(refreshed.AccessToken)
	require.NoError(t, err, "could not verify new access token")
	require.NotNil(t, newVerified, "new verified claims should not be nil")
	require.Equal(t, refreshed.Claims.Name, newVerified.Name, "name should match")
	require.Equal(t, refreshed.Claims.Email, newVerified.Email, "email should match")

	// Should manage 304 not modified responses
	err = qd.Sync()
	require.NoError(t, err, "could not synchronize Quarterdeck")
}
