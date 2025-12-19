package semconv

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/semconv/v1.37.0/httpconv"
)

type RequestTraceAttrsOpts struct {
	// If set, this is used as value for the "http.client_ip" attribute.
	HTTPClientIP string
}

type ResponseTelemetry struct {
	StatusCode int
	ReadBytes  int64
	ReadError  error
	WriteBytes int64
	WriteError error
}

type HTTPServer struct {
	requestBodySizeHistogram  httpconv.ServerRequestBodySize
	responseBodySizeHistogram httpconv.ServerResponseBodySize
	requestDurationHistogram  httpconv.ServerRequestDuration
}

func NewHTTPServer(meter metric.Meter) HTTPServer {
	server := HTTPServer{}

	var err error
	server.requestBodySizeHistogram, err = httpconv.NewServerRequestBodySize(meter)
	handleErr(err)

	server.responseBodySizeHistogram, err = httpconv.NewServerResponseBodySize(meter)
	handleErr(err)

	server.requestDurationHistogram, err = httpconv.NewServerRequestDuration(
		meter,
		metric.WithExplicitBucketBoundaries(
			0.005, 0.01, 0.025, 0.05, 0.075, 0.1,
			0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10,
		),
	)
	handleErr(err)
	return server
}

// Status returns a span status code and message for an HTTP status code
// value returned by a server. Status codes in the 400-499 range are not
// returned as errors.
func (n HTTPServer) Status(code int) (codes.Code, string) {
	if code < 100 || code >= 600 {
		return codes.Error, fmt.Sprintf("Invalid HTTP status code %d", code)
	}
	if code >= 500 {
		return codes.Error, ""
	}
	return codes.Unset, ""
}

// Route returns the attribute for the route.
func (n HTTPServer) Route(route string) attribute.KeyValue {
	return semconv.HTTPRoute(route)
}

func (n HTTPServer) RequestTraceAttrs(server string, req *http.Request, opts RequestTraceAttrsOpts) []attribute.KeyValue {
	return nil
}

func (n HTTPServer) ReponseTraceAttrs(telemetry ResponseTelemetry) []attribute.KeyValue {
	return nil
}

func (n HTTPServer) RecordMetrics(ctx context.Context, data ServerMetricData) {
}
