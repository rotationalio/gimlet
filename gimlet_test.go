package gimlet_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet"
)

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

	data := &gimlet.ErrorReply{}
	err := json.NewDecoder(rep.Body).Decode(data)
	require.NoError(t, err, "could not parse response body")

	require.False(t, data.Success, "expected success to be false")
	require.Equal(t, expectedError, data.Err, "expected error message to match")
}

func ReadJSON(rep *http.Response) (*gimlet.ErrorReply, error) {
	defer rep.Body.Close()
	data := &gimlet.ErrorReply{}
	if err := json.NewDecoder(rep.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}
