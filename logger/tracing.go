package logger

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
)

func Tracing(c any) *slog.Logger {
	requestID, ok := RequestID(c)
	if ok {
		return slog.Default().With(slog.String("request_id", requestID))
	}
	return slog.Default()
}

func SetRequestID(c *gin.Context, requestID string) {
	gimlet.SetBoth(c, gimlet.KeyRequestID, requestID)
}

func RequestID(c any) (string, bool) {
	if val, exists := gimlet.Get(c, gimlet.KeyRequestID); exists {
		requestID, ok := val.(string)
		return requestID, ok
	}
	return "", false
}
