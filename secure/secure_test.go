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
}

func handler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true})
}
