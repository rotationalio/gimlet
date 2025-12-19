package semconv

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
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
