package secure_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/secure"
)

func TestCSPDirectives(t *testing.T) {
	testCases := []struct {
		config   secure.CSPDirectives
		expected string
	}{
		{config: secure.CSPDirectives{}, expected: ""},
		{
			config: secure.CSPDirectives{
				DefaultSrc: []string{"https:"},
			},
			expected: "default-src https:",
		},
		{
			config: secure.CSPDirectives{
				DefaultSrc: []string{"https:", secure.UnsafeEval, secure.UnsafeInline},
				ObjectSrc:  []string{secure.None},
			},
			expected: "default-src https: 'unsafe-eval' 'unsafe-inline'; object-src 'none'",
		},
		{
			config: secure.CSPDirectives{
				DefaultSrc: []string{"https:"},
				ReportTo:   "csp-endpoint",
			},
			expected: "default-src https:; report-to csp-endpoint",
		},
		{
			config: secure.CSPDirectives{
				DefaultSrc:              []string{"https:"},
				UpgradeInsecureRequests: true,
			},
			expected: "default-src https:; upgrade-insecure-requests",
		},
	}

	for i, tc := range testCases {
		require.Equal(t, tc.expected, tc.config.Directive(), "test case %d", i)
	}
}

func TestCSPDirectivesIsZero(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		testCases := []secure.CSPDirectives{
			{},
			{nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "", nil, nil, false},
			{[]string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, "", []string{}, []string{}, false},
		}

		for i, tc := range testCases {
			require.True(t, tc.IsZero(), "should be zero test case %d", i)
		}
	})

	t.Run("NonEmpty", func(t *testing.T) {
		testCases := []secure.CSPDirectives{
			{ChildSrc: []string{"'self'"}},
			{ConnectSrc: []string{"'self'"}},
			{DefaultSrc: []string{"'self'"}},
			{FencedFrameSrc: []string{"'self'"}},
			{FontSrc: []string{"'self'"}},
			{FrameSrc: []string{"'self'"}},
			{ImgSrc: []string{"'self'"}},
			{ManifestSrc: []string{"'self'"}},
			{MediaSrc: []string{"'self'"}},
			{ObjectSrc: []string{"'self'"}},
			{PrefetchSrc: []string{"'self'"}},
			{ScriptSrc: []string{"'self'"}},
			{ScriptSrcElem: []string{"'self'"}},
			{ScriptSrcAttr: []string{"'self'"}},
			{StyleSrc: []string{"'self'"}},
			{StyleSrcElem: []string{"'self'"}},
			{StyleSrcAttr: []string{"'self'"}},
			{WorkerSrc: []string{"'self'"}},
			{BaseURI: []string{"'self'"}},
			{Sandbox: []string{"allow-same-origin", "allow-scripts"}},
			{FormAction: []string{"'self'"}},
			{FrameAncestors: []string{"'self'"}},
			{ReportTo: "/report-endpoint"},
			{RequireTrustedTypesFor: []string{"script"}},
			{TrustedTypes: []string{"default"}},
			{UpgradeInsecureRequests: true},
		}

		for i, tc := range testCases {
			require.False(t, tc.IsZero(), "should be non-zero test case %d", i)
		}
	})
}
