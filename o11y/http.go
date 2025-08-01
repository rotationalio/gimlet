package o11y

import "github.com/prometheus/client_golang/prometheus"

const (
	NamespaceHTTPMetrics = "http_stats"
)

var (
	// Total HTTP requests handled by the server; labeled by service, method, code, and path
	RequestsHandled *prometheus.CounterVec

	// HTTP Request duration (latency); labeled by service, method, code, and path
	RequestDuration *prometheus.HistogramVec

	// HTTP Request size; labeled by service, method, code, and path
	RequestSize *prometheus.HistogramVec

	// HTTP Response size; labeled by service, method, code, and path
	ResponseSize *prometheus.HistogramVec
)

var labelNames = []string{"service", "method", "code", "path"}

func initHTTPCollectors() (collectors []prometheus.Collector, err error) {
	collectors = make([]prometheus.Collector, 0, 4)

	RequestsHandled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: NamespaceHTTPMetrics,
		Name:      "requests_handled",
		Help:      "total number of http requests handled by the server, labeled by service, method, code, and path",
	}, labelNames)
	collectors = append(collectors, RequestsHandled)

	RequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: NamespaceHTTPMetrics,
		Name:      "request_duration",
		Help:      "duration of http requests in seconds, labeled by service, method, code, and path",
		Buckets:   prometheus.DefBuckets,
	}, labelNames)
	collectors = append(collectors, RequestDuration)

	RequestSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: NamespaceHTTPMetrics,
		Name:      "request_size",
		Help:      "size of http requests in bytes, labeled by service, method, code, and path",
		Buckets:   prometheus.ExponentialBuckets(100, 2, 12), // 100 bytes to 409,600 bytes
	}, labelNames)
	collectors = append(collectors, RequestSize)

	ResponseSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: NamespaceHTTPMetrics,
		Name:      "response_size",
		Help:      "size of http responses in bytes, labeled by service, method, code, and path",
		Buckets:   prometheus.ExponentialBuckets(100, 2, 16), // 100 bytes to 6,553,600 bytes
	}, labelNames)
	collectors = append(collectors, ResponseSize)

	return collectors, nil
}
