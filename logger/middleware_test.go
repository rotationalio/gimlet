package logger_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/logger"
)

var expectedKeys = []string{
	"path", "service", "version", "method", "resp_time",
	"resp_bytes", "status", "client_ip", "request_id",
	"level", "message", "severity", "time",
}

func TestLogger(t *testing.T) {
	sink := logger.TestSink()
	defer logger.ResetLogger()

	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.Use(logger.Logger("testing", "1.2.3"))

	// This handler returns a 200 OK response
	router.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// This handler returns a 400 Bad Request response with one gin error
	router.GET("/bad", func(c *gin.Context) {
		c.Error(errors.New("could not parse request"))
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
	})

	// This handler returns a 500 Internal Server Error response with multiple gin errors
	router.GET("/err", func(c *gin.Context) {
		c.Error(errors.New("could not connect to database"))
		c.Error(errors.New("nil fiield response returned"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	})

	srv := httptest.NewServer(router)
	defer srv.Close()

	t.Run("Ok", func(t *testing.T) {
		t.Cleanup(sink.Reset)

		rep, err := srv.Client().Get(srv.URL + "/ok")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rep.StatusCode)

		record := sink.Get(0)
		require.NotNil(t, record, "expected log record to be created")
		require.Equal(t, "info", record["level"], "expected log level to be info")
		require.NotContains(t, record, "errors", "expected log record to not contain errors key")

		for _, key := range expectedKeys {
			require.Contains(t, record, key, "expected log record to contain key: "+key)
			require.NotEmpty(t, record[key], "expected log record key %s to not be empty", key)
		}
	})

	t.Run("Bad", func(t *testing.T) {
		t.Cleanup(sink.Reset)

		rep, err := srv.Client().Get(srv.URL + "/bad")
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rep.StatusCode)

		record := sink.Get(0)
		require.NotNil(t, record, "expected log record to be created")
		require.Equal(t, "warn", record["level"], "expected log level to be warn")
		require.Contains(t, record, "errors", "expected log record to contain errors key")
		require.Len(t, record["errors"], 1, "expected log record to contain one error")

		for _, key := range expectedKeys {
			require.Contains(t, record, key, "expected log record to contain key: "+key)
			require.NotEmpty(t, record[key], "expected log record key %s to not be empty", key)
		}
	})

	t.Run("Error", func(t *testing.T) {
		t.Cleanup(sink.Reset)

		rep, err := srv.Client().Get(srv.URL + "/err")
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, rep.StatusCode)

		record := sink.Get(0)
		require.NotNil(t, record, "expected log record to be created")
		require.Equal(t, "error", record["level"], "expected log level to be error")
		require.Contains(t, record, "errors", "expected log record to contain errors key")
		require.Len(t, record["errors"], 2, "expected log record to contain two errors")

		for _, key := range expectedKeys {
			require.Contains(t, record, key, "expected log record to contain key: "+key)
			require.NotEmpty(t, record[key], "expected log record key %s to not be empty", key)
		}
	})
}
