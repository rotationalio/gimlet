package logger

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/x/rlog"
)

func Tracing(c any) *rlog.Logger {
	requestID, ok := RequestID(c)
	if ok {
		return rlog.New(rlog.Default().With(slog.String("request_id", requestID)))
	}
	return rlog.Default()
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
