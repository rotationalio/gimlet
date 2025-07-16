package auth_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	. "go.rtnl.ai/gimlet/auth"
	"go.rtnl.ai/ulid"
)

func TestSubjectType(t *testing.T) {
	id := ulid.MustParse("01HVEH4E88XMYDXFAE4Y48CE9F")

	t.Run("User", func(t *testing.T) {
		claims := &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "u01HVEH4E88XMYDXFAE4Y48CE9F",
			},
		}

		sub, pid, err := claims.SubjectID()
		require.NoError(t, err)
		require.Equal(t, pid, id)
		require.Equal(t, SubjectUser, sub)
	})

	t.Run("APIKey", func(t *testing.T) {
		claims := &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "k01HVEH4E88XMYDXFAE4Y48CE9F",
			},
		}

		sub, pid, err := claims.SubjectID()
		require.NoError(t, err)
		require.Equal(t, pid, id)
		require.Equal(t, SubjectAPIKey, sub)
	})

	t.Run("Vero", func(t *testing.T) {
		claims := &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "v01HVEH4E88XMYDXFAE4Y48CE9F",
			},
		}

		sub, pid, err := claims.SubjectID()
		require.NoError(t, err)
		require.Equal(t, pid, id)
		require.Equal(t, SubjectVero, sub)
	})

	t.Run("Unknown", func(t *testing.T) {
		claims := &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "b01HVEH4E88XMYDXFAE4Y48CE9F",
			},
		}

		sub, pid, err := claims.SubjectID()
		require.NoError(t, err)
		require.Equal(t, pid, id)
		require.Equal(t, SubjectType('b'), sub)
	})
}

func TestClaimsHasPermission(t *testing.T) {
	claims := &Claims{
		Permissions: []string{"foo:manage", "foo:view", "foo:delete", "bar:view"},
	}

	for _, permission := range []string{"foo:manage", "foo:view", "foo:delete", "bar:view"} {
		require.True(t, claims.HasPermission(permission), "expected claims to have permission %q", permission)
	}

	for _, permission := range []string{"", "bar:manage", "bar:delete", "FOO:VIEW"} {
		require.False(t, claims.HasPermission(permission), "expected claims to not have permission %q", permission)
	}
}

func TestClaimsHasAllPermissions(t *testing.T) {
	claims := &Claims{
		Permissions: []string{"foo:manage", "foo:view", "foo:delete", "bar:view"},
	}

	tests := []struct {
		required []string
		assert   require.BoolAssertionFunc
	}{
		{
			[]string{},
			require.False,
		},
		{
			[]string{"foo:view", "bar:manage"},
			require.False,
		},
		{
			[]string{"foo:manage", "foo:view", "foo:delete", "bar:manage"},
			require.False,
		},
		{
			[]string{"foo:view"},
			require.True,
		},
		{
			[]string{"bar:view"},
			require.True,
		},
		{
			[]string{"foo:manage", "foo:view", "foo:delete", "bar:view"},
			require.True,
		},
		{
			[]string{"foo:view", "foo:delete"},
			require.True,
		},
	}

	for i, tc := range tests {
		tc.assert(t, claims.HasAllPermissions(tc.required...), "test case %d failed", i)
	}
}

func TestSubjectString(t *testing.T) {
	tests := []struct {
		subjectType SubjectType
		expected    string
	}{
		{SubjectUser, "user"},
		{SubjectAPIKey, "apikey"},
		{SubjectVero, "vero"},
		{SubjectType('!'), "unknown"},
	}

	for _, test := range tests {
		require.Equal(t, test.expected, test.subjectType.String(), "expected subject type %q to be %q", test.subjectType, test.expected)
	}
}
