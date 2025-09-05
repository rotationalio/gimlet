package secure_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/secure"
)

func TestSecure(t *testing.T) {
	execTest := func(t *testing.T, secure gin.HandlerFunc, expected map[string]string) {
		router := gin.New()
		router.Use(secure)
		router.GET("/", handler)

		srv := httptest.NewTLSServer(router)
		defer srv.Close()

		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)

		rep, err := srv.Client().Do(req)
		require.NoError(t, err)

		for header, value := range expected {
			require.Equal(t, value, rep.Header.Get(header), "header %q", header)
		}
	}

	t.Run("Defaults", func(t *testing.T) {
		execTest(t, secure.Secure(nil), map[string]string{
			secure.HeaderContentTypeNosniff:      secure.NoSniff,
			secure.HeaderReferrerPolicy:          secure.StrictOriginWhenCrossOrigin,
			secure.HeaderCrossOriginOpenerPolicy: secure.SameOrigin,
			secure.HeaderStrictTransportSecurity: "",
		})
	})

	t.Run("Recommended", func(t *testing.T) {
		execTest(t, secure.Secure(&secure.Config{
			ContentTypeNosniff:      true,
			ReferrerPolicy:          secure.StrictOrigin,
			CrossOriginOpenerPolicy: secure.SameOriginAllowPopups,
			HSTS: secure.HSTSConfig{
				Seconds:           31536000,
				IncludeSubdomains: true,
				Preload:           true,
			},
		}), map[string]string{
			secure.HeaderContentTypeNosniff:      secure.NoSniff,
			secure.HeaderReferrerPolicy:          secure.StrictOrigin,
			secure.HeaderCrossOriginOpenerPolicy: secure.SameOriginAllowPopups,
			secure.HeaderStrictTransportSecurity: "max-age=31536000; includeSubDomains; preload",
		})
	})

	t.Run("CSP", func(t *testing.T) {
		execTest(t, secure.Secure(&secure.Config{
			ReferrerPolicy:          secure.NoPolicy,
			CrossOriginOpenerPolicy: secure.NoPolicy,
			ContentSecurityPolicy: secure.CSPDirectives{
				DefaultSrc: []string{"https:"},
				ScriptSrc:  []string{"'self'", "*.cloudflare.com"},
				StyleSrc:   []string{"'self'", "'unsafe-inline'", "*.cloudflare.com"},
			},
			ContentSecurityPolicyReportOnly: secure.CSPDirectives{
				ScriptSrc:               []string{"https:", "*.cdndirect.com"},
				StyleSrc:                []string{"https:", "*.cdndirect.com"},
				ReportTo:                "csp-endpoint",
				UpgradeInsecureRequests: true,
			},
			ReportingEndpoints: map[string]string{"csp-endpoint": "https://example.com/csp-reports"},
		}), map[string]string{
			secure.HeaderContentTypeNosniff:      "",
			secure.HeaderReferrerPolicy:          "",
			secure.HeaderCrossOriginOpenerPolicy: "",
			secure.HeaderStrictTransportSecurity: "",
			secure.HeaderContentSecurityPolicy:   "default-src https:; script-src 'self' *.cloudflare.com; style-src 'self' 'unsafe-inline' *.cloudflare.com",
			secure.HeaderCSPReportOnly:           `script-src https: *.cdndirect.com; style-src https: *.cdndirect.com; upgrade-insecure-requests; report-to csp-endpoint`,
			secure.HeaderReportingEndpoints:      `csp-endpoint="https://example.com/csp-reports"`,
		})
	})
}

func handler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func TestReportingEndpoints(t *testing.T) {
	testCases := []struct {
		endpoints map[string]string
		expected  string
	}{
		{endpoints: nil, expected: ""},
		{endpoints: map[string]string{}, expected: ""},
		{endpoints: map[string]string{"csp-endpoint": "https://example.com/csp-reports"}, expected: `csp-endpoint="https://example.com/csp-reports"`},
		{endpoints: map[string]string{"csp-endpoint": "https://example.com/csp-reports", "permissions-endpoint": "https://example.com/permissions"}, expected: `csp-endpoint="https://example.com/csp-reports", permissions-endpoint="https://example.com/permissions"`},
	}

	for i, tc := range testCases {
		// HACK: golang dictionaries do not guarantee order on iteration so this test can fail
		// TODO: use a regular expression to validate the output or use a sorted structure
		require.Equal(t, tc.expected, secure.ReportingEndpoints(tc.endpoints), "test case %d", i)
	}
}
