package logger_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.rtnl.ai/gimlet/logger"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/ulid"
)

func TestTracing(t *testing.T) {
	// Without a request ID
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)

	sink := logger.TestSink()
	defer logger.ResetLogger()

	log := logger.Tracing(c)
	log.Info().Msg("duck")
	record := sink.Get(0)
	require.NotNil(t, record, "expected log record to be created")
	require.Contains(t, record, "message", "expected correct log message")
	require.Equal(t, "duck", record["message"], "expected log message to match")
	require.NotContains(t, record, "request_id", "expected log without request ID")

	// Reset the sink for the next test
	sink.Reset()

	// With a request ID
	requestID := "testreq"
	logger.SetRequestID(c, requestID)

	log = logger.Tracing(c)
	log.Info().Msg("goose")

	record = sink.Get(0)
	require.NotNil(t, record, "expected log record to be created")
	require.Contains(t, record, "message", "expected correct log message")
	require.Equal(t, "goose", record["message"], "expected log message to match")
	require.Contains(t, record, "request_id", "expected log with request ID")
	require.Equal(t, requestID, record["request_id"], "expected log request ID to match")
}

func TestRequestIDContext(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)

	// Should be no request ID on the context initially
	_, exists := logger.RequestID(c)
	require.False(t, exists, "Expected no request ID in context before setting")

	// Create a request ID for tracing purposes and add to context
	requestID := ulid.Make().String()
	logger.SetRequestID(c, requestID)

	// Retrieve the request ID from the context
	retrievedID, ok := logger.RequestID(c)
	require.True(t, ok, "Expected request ID to be set in context")
	require.Equal(t, requestID, retrievedID, "Expected retrieved request ID to match original")
}
