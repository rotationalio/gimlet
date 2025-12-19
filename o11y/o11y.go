/*
Package o11y instruments the github.com/gin-gonic/gin package.

This package provides middleware that instruments the routing of a received message.

Based on go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin
*/
package o11y

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.rtnl.ai/gimlet/o11y/internal/semconv"
)

const (
	tracerKey = "rotational-gimlet-tracer"

	ScopeName = "go.rtnl.ai/gimlet/o11y"
)

// Middleware returns middleware that will trace incoming requests.
// The service pramater should describe the name of the (virtual) server handling
// the request; e.g. the name of the service.
func Middleware(service string, opts ...Option) gin.HandlerFunc {
	cfg := configure(opts...)

	// Setup OpenTelemetry components.
	tracer := cfg.TracerProvider.Tracer(ScopeName)
	meter := cfg.MeterProvider.Meter(ScopeName)
	sc := semconv.NewHTTPServer(meter)

	return func(c *gin.Context) {
		// Before Request
		started := time.Now()

		// Apply filters if any filter returns false, do not trace the request.
		if !cfg.filter(c) {
			c.Next()
			return
		}

		// Begin tracing request
		c.Set(tracerKey, tracer)

		// Replace the original context when tracing is complete.
		savedCtx := c.Request.Context()
		defer func() {
			c.Request = c.Request.WithContext(savedCtx)
		}()

		// Create new context for the span
		ctx := cfg.Propagators.Extract(savedCtx, propagation.HeaderCarrier(c.Request.Header))

		requestTraceAttrOpts := semconv.RequestTraceAttrsOpts{
			// Gin's ClientIP method can detect the client's IP from various headers set by proxies, and it's configurable
			HTTPClientIP: c.ClientIP(),
		}

		opts := []trace.SpanStartOption{
			trace.WithAttributes(sc.RequestTraceAttrs(service, c.Request, requestTraceAttrOpts)...),
			trace.WithAttributes(sc.Route(c.FullPath())),
			trace.WithSpanKind(trace.SpanKindServer),
		}

		opts = append(opts, cfg.SpanStartOptions...)

		spanName := cfg.SpanNameFormatter(c)
		if spanName == "" {
			spanName = fmt.Sprintf("HTTP %s route not found", c.Request.Method)
		}
		ctx, span := tracer.Start(ctx, spanName, opts...)
		defer span.End()

		// Pass the span through the request context and serve the request to next middleware
		c.Request = c.Request.WithContext(ctx)
		c.Next()

		// Set span status and response telemetry
		status := c.Writer.Status()
		span.SetStatus(sc.Status(status))

		span.SetAttributes(sc.ReponseTraceAttrs(semconv.ResponseTelemetry{
			StatusCode: status,
			WriteBytes: int64(c.Writer.Size()),
		})...)

		// Handle errors associated with the gin context.
		// NOTE: this means we should put errors onto the gin context and not directly
		// onto the span to have them recorded in application code.
		if len(c.Errors) > 0 {
			span.SetStatus(codes.Error, c.Errors.String())
			for _, err := range c.Errors {
				span.RecordError(err)
			}
		}

		// Record server-side attributes
		var additional []attribute.KeyValue
		if c.FullPath() != "" {
			additional = append(additional, sc.Route(c.FullPath()))
		}
		if cfg.MetricAttributeFn != nil {
			additional = append(additional, cfg.MetricAttributeFn(c.Request)...)
		}
		if cfg.GinMetricAttributeFn != nil {
			additional = append(additional, cfg.GinMetricAttributeFn(c)...)
		}

		// Record metrics
		sc.RecordMetrics(ctx, semconv.ServerMetricData{
			ServerName:   service,
			ResponseSize: int64(c.Writer.Size()),
			MetricAttributes: semconv.MetricAttributes{
				Req:        c.Request,
				StatusCode: status,
				Additional: additional,
			},
			MetricData: semconv.MetricData{
				RequestSize: c.Request.ContentLength,
				ElapsedTime: float64(time.Since(started)) / float64(time.Millisecond),
			},
		})
	}
}

func (cfg config) filter(c *gin.Context) bool {
	for _, f := range cfg.Filters {
		if !f(c.Request) {
			return false
		}
	}

	for _, f := range cfg.GinFilters {
		if !f(c) {
			return false
		}
	}

	return true
}
