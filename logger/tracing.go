package logger

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.rtnl.ai/gimlet"
)

func Tracing(c any) zerolog.Logger {
	requestID, ok := RequestID(c)
	if ok {
		return log.With().Str("request_id", requestID).Logger()
	}
	return log.With().Logger()
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
