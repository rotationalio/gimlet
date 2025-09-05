package secure_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/secure"
)

func TestConfigValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		testCases := []secure.Config{
			{ReferrerPolicy: "strict-origin-when-cross-origin", CrossOriginOpenerPolicy: "same-origin"},
			{ReferrerPolicy: "NO-REFERRER", CrossOriginOpenerPolicy: "same-origin-ALLOW-POPUPS"},
			{ReferrerPolicy: " strict-origin ", CrossOriginOpenerPolicy: "unsafe-none"},
			{ReferrerPolicy: "no-referrer-when-downgrade", CrossOriginOpenerPolicy: "same-origin"},
			{ReferrerPolicy: "origin", CrossOriginOpenerPolicy: "same-origin"},
			{ReferrerPolicy: "origin-when-cross-origin", CrossOriginOpenerPolicy: "same-origin"},
			{ReferrerPolicy: "unsafe-url", CrossOriginOpenerPolicy: "same-origin"},
		}

		for i, tc := range testCases {
			require.NoError(t, tc.Validate(), "could not validate test case %d", i)
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		testCases := []secure.Config{
			{},
			{ReferrerPolicy: "invalid"},
			{CrossOriginOpenerPolicy: "invalid"},
			{ReferrerPolicy: "invalid", CrossOriginOpenerPolicy: "invalid"},
		}

		for i, tc := range testCases {
			require.Error(t, tc.Validate(), "should not validate test case %d", i)
		}
	})
}

func TestHSTSDirective(t *testing.T) {
	testCases := []struct {
		config   secure.HSTSConfig
		expected string
	}{
		{config: secure.HSTSConfig{Seconds: 0}, expected: ""},
		{config: secure.HSTSConfig{Seconds: -10}, expected: ""},
		{config: secure.HSTSConfig{Seconds: 31536000}, expected: "max-age=31536000"},
		{config: secure.HSTSConfig{Seconds: 31536000, IncludeSubdomains: true}, expected: "max-age=31536000; includeSubDomains"},
		{config: secure.HSTSConfig{Seconds: 31536000, IncludeSubdomains: true, Preload: true}, expected: "max-age=31536000; includeSubDomains; preload"},
		{config: secure.HSTSConfig{Seconds: 31536000, Preload: true}, expected: "max-age=31536000"},
	}

	for i, tc := range testCases {
		require.Equal(t, tc.expected, tc.config.Directive(), "test case %d", i)
	}
}
