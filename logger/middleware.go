package logger

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/ulid"
	"go.rtnl.ai/x/rlog"
)

const (
	LogLevelKey = "logger.level"
)

// Logger returns a new Gin middleware that performs logging for our JSON APIs using
// [go.rtnl.ai/x/rlog] rather than the default Gin logger which is a standard
// HTTP logger.
func Logger(service, version string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Before request
		started := time.Now()

		path := c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			path = path + "?" + c.Request.URL.RawQuery
		}

		// Create a request ID for tracing purposes and add to context
		requestID := ulid.Make().String()
		SetRequestID(c, requestID)

		// Handle the request
		c.Next()

		// After request
		status := c.Writer.Status()

		// Log any errors that were added to the context
		attrs := []slog.Attr{
			slog.String("path", path),
			slog.String("service", service),
			slog.String("version", version),
			slog.String("method", c.Request.Method),
			slog.Duration("resp_time", time.Since(started)),
			slog.Int("resp_bytes", c.Writer.Size()),
			slog.Int("status", status),
			slog.String("client_ip", c.ClientIP()),
			slog.String("request_id", requestID),
		}
		if len(c.Errors) > 0 {
			errs := make([]error, 0, len(c.Errors))
			for _, err := range c.Errors {
				errs = append(errs, err)
			}
			attrs = append(attrs, slog.Any("errors", errs))
		}

		// Create the message to send to the logger.
		var msg string
		switch len(c.Errors) {
		case 0, 1:
			msg = fmt.Sprintf("%s %s %s %d", service, c.Request.Method, c.Request.URL.Path, status)
		default:
			msg = fmt.Sprintf("%s %s %s [%d] %d errors occurred", service, c.Request.Method, c.Request.URL.Path, status, len(c.Errors))
		}

		ctx := c.Request.Context()
		if ll, ok := c.Get(LogLevelKey); ok {
			if level, ok := ll.(slog.Level); ok {
				rlog.LogAttrs(ctx, level, msg, attrs...)
				return
			}
		}

		switch {
		case status >= 400 && status < 500:
			rlog.WarnAttrs(ctx, msg, attrs...)
		case status >= 500:
			rlog.ErrorAttrs(ctx, msg, attrs...)
		default:
			rlog.InfoAttrs(ctx, msg, attrs...)
		}
	}
}
