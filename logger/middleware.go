package logger

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"go.rtnl.ai/gimlet/o11y"
	"go.rtnl.ai/ulid"
)

// Logger returns a new Gin middleware that performs logging for our JSON APIs using
// zerolog rather than the default Gin logger which is a standard HTTP logger.
// NOTE: we previously used github.com/dn365/gin-zerolog but wanted more customization.
func Logger(service, version string, withMetrics bool) gin.HandlerFunc {
	if withMetrics {
		if err := o11y.Setup(); err != nil {
			log.Error().Err(err).Msg("failed to setup o11y metrics")
			withMetrics = false
		}
	}

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
		logctx := log.With().
			Str("path", path).
			Str("service", service).
			Str("version", version).
			Str("method", c.Request.Method).
			Dur("resp_time", time.Since(started)).
			Int("resp_bytes", c.Writer.Size()).
			Int("status", status).
			Str("client_ip", c.ClientIP()).
			Str("request_id", requestID).
			Logger()

		// Log any errors that were added to the context
		if len(c.Errors) > 0 {
			errs := make([]error, 0, len(c.Errors))
			for _, err := range c.Errors {
				errs = append(errs, err)
			}
			logctx = logctx.With().Errs("errors", errs).Logger()
		}

		// Create the message to send to the logger.
		var msg string
		switch len(c.Errors) {
		case 0, 1:
			msg = fmt.Sprintf("%s %s %s %d", service, c.Request.Method, c.Request.URL.Path, status)
		default:
			msg = fmt.Sprintf("%s %s %s [%d] %d errors occurred", service, c.Request.Method, c.Request.URL.Path, status, len(c.Errors))
		}

		switch {
		case status >= 400 && status < 500:
			logctx.Warn().Msg(msg)
		case status >= 500:
			logctx.Error().Msg(msg)
		default:
			logctx.Info().Msg(msg)
		}

		if withMetrics {
			statusText := http.StatusText(status)
			o11y.RequestsHandled.WithLabelValues(service, c.Request.Method, statusText, path).Inc()
			o11y.RequestDuration.WithLabelValues(service, c.Request.Method, statusText, path).Observe(time.Since(started).Seconds())
			o11y.RequestSize.WithLabelValues(service, c.Request.Method, statusText, path).Observe(float64(c.Request.ContentLength))
			o11y.ResponseSize.WithLabelValues(service, c.Request.Method, statusText, path).Observe(float64(c.Writer.Size()))
		}
	}
}
