package semconv

import (
	"net/http"
	"slices"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

type ServerMetricData struct {
	ServerName   string
	ResponseSize int64

	MetricData
	MetricAttributes
}

type MetricAttributes struct {
	Req        *http.Request
	StatusCode int
	Route      string
	Additional []attribute.KeyValue
}

type MetricData struct {
	RequestSize int64

	// The request duration, in milliseconds
	ElapsedTime float64
}

func (md ServerMetricData) Attributes() []attribute.KeyValue {
	// Grow the attributes slice to fit all possible attributes.
	attrs := slices.Grow(md.Additional, 8)

	var (
		host string
		p    int
	)

	if md.ServerName == "" {
		host, p = SplitHostPort(md.Req.Host)
	} else {
		// Prioritize primary server name.
		host, p = SplitHostPort(md.ServerName)
		if p < 0 {
			_, p = SplitHostPort(md.Req.Host)
		}
	}

	attrs = append(attrs,
		semconv.HTTPRequestMethodKey.String(standardizeHTTPMethod(md.Req.Method)),
		scheme(md.Req.TLS != nil),
		semconv.ServerAddress(host),
	)

	if hostPort := requiredHTTPPort(md.Req.TLS != nil, p); hostPort > 0 {
		attrs = append(attrs, semconv.ServerPort(hostPort))
	}

	protoName, protoVersion := netProtocol(md.Req.Proto)
	if protoName != "" {
		attrs = append(attrs, semconv.NetworkProtocolName(protoName))
	}
	if protoVersion != "" {
		attrs = append(attrs, semconv.NetworkProtocolVersion(protoVersion))
	}

	if md.StatusCode > 0 {
		attrs = append(attrs, semconv.HTTPResponseStatusCode(md.StatusCode))
	}

	if md.Route != "" {
		attrs = append(attrs, semconv.HTTPRoute(md.Route))
	}

	return slices.Clip(attrs)
}
