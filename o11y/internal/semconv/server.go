package semconv

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

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

// Returns trace attributes for an HTTP request received by a server.
//
// The server must be the primary server name if it is known. E.g. the server name
// directive in an Apache or Nginx configuration. More generically, the primary server
// name would be the host header value that matches the default virtual host of an
// HTTP server. It should include the host identifier and if a port is used to route
// to the server that port identifier should be included as an appropriate port suffix.
// If this nae is not known, server should be an empty string.
func (n HTTPServer) RequestTraceAttrs(server string, req *http.Request, opts RequestTraceAttrsOpts) []attribute.KeyValue {
	// The number of attrs for slice creation
	count := 3 // address, method, scheme

	// Determine the host and port from the server or request Host header
	var (
		host string
		p    int
	)

	if server == "" {
		host, p = SplitHostPort(req.Host)
	} else {
		host, p = SplitHostPort(server)
		if p < 0 {
			_, p = SplitHostPort(req.Host)
		}
	}

	hostPort := requiredHTTPPort(req.TLS != nil, p)
	if hostPort > 0 {
		count++
	}

	method, methodOriginal := n.method(req.Method)
	if methodOriginal != (attribute.KeyValue{}) {
		count++
	}

	scheme := scheme(req.TLS != nil)

	peer, peerPort := SplitHostPort(req.RemoteAddr)
	if peer != "" {
		count++
		if peerPort > 0 {
			count++
		}
	}

	useragent := req.UserAgent()
	if useragent != "" {
		count++
	}

	// Client IP discovery order:
	// 1. Value passed in options
	// 2. X-Forwarded-For header
	// 3. The peer address
	clientIP := opts.HTTPClientIP
	if clientIP == "" {
		clientIP = serverClientIP(req.Header.Get("X-Forwarded-For"))
		if clientIP == "" {
			clientIP = peer
		}
	}
	if clientIP != "" {
		count++
	}

	if req.URL != nil && req.URL.Path != "" {
		count++
	}

	protoName, protoVersion := netProtocol(req.Proto)
	if protoName != "" && protoName != "http" {
		count++
	}
	if protoVersion != "" {
		count++
	}

	route := httpRoute(req.Pattern)
	if route != "" {
		count++
	}

	attrs := make([]attribute.KeyValue, 0, count)
	attrs = append(attrs, semconv.ServerAddress(host), method, scheme)

	if hostPort > 0 {
		attrs = append(attrs, semconv.ServerPort(hostPort))
	}
	if methodOriginal != (attribute.KeyValue{}) {
		attrs = append(attrs, methodOriginal)
	}

	if peer != "" {
		attrs = append(attrs, semconv.NetworkPeerAddress(peer))
		if peerPort > 0 {
			attrs = append(attrs, semconv.NetworkPeerPort(peerPort))
		}
	}

	if useragent != "" {
		attrs = append(attrs, semconv.UserAgentOriginal(useragent))
	}

	if clientIP != "" {
		attrs = append(attrs, semconv.ClientAddress(clientIP))
	}

	if req.URL != nil && req.URL.Path != "" {
		attrs = append(attrs, semconv.URLPath(req.URL.Path))
	}

	if protoName != "" && protoName != "http" {
		attrs = append(attrs, semconv.NetworkProtocolName(protoName))
	}
	if protoVersion != "" {
		attrs = append(attrs, semconv.NetworkProtocolVersion(protoVersion))
	}

	if route != "" {
		attrs = append(attrs, n.Route(route))
	}

	return attrs
}

func (n HTTPServer) ResponseTraceAttrs(rep ResponseTelemetry) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 3)

	if rep.ReadBytes > 0 {
		attrs = append(attrs, semconv.HTTPRequestBodySize(int(rep.ReadBytes)))
	}

	if rep.WriteBytes > 0 {
		attrs = append(attrs, semconv.HTTPResponseBodySize(int(rep.WriteBytes)))
	}

	if rep.StatusCode > 0 {
		attrs = append(attrs, semconv.HTTPResponseStatusCode(rep.StatusCode))
	}

	return slices.Clip(attrs)
}

var (
	metricRecordOptionPool = &sync.Pool{
		New: func() any {
			return &[]metric.RecordOption{}
		},
	}
)

func (n HTTPServer) RecordMetrics(ctx context.Context, md ServerMetricData) {
	attrs := md.Attributes()

	o := metric.WithAttributeSet(attribute.NewSet(attrs...))
	opts := metricRecordOptionPool.Get().(*[]metric.RecordOption)
	*opts = append(*opts, o)

	n.requestBodySizeHistogram.Inst().Record(ctx, md.RequestSize, *opts...)
	n.responseBodySizeHistogram.Inst().Record(ctx, md.ResponseSize, *opts...)
	n.requestDurationHistogram.Inst().Record(ctx, md.ElapsedTime/1000.0, o)

	*opts = (*opts)[:0]
	metricRecordOptionPool.Put(opts)
}

func (n HTTPServer) method(method string) (attribute.KeyValue, attribute.KeyValue) {
	if method == "" {
		return semconv.HTTPRequestMethodGet, attribute.KeyValue{}
	}

	if attr, ok := methodLookup[method]; ok {
		return attr, attribute.KeyValue{}
	}

	orig := semconv.HTTPRequestMethodOriginal(method)
	if attr, ok := methodLookup[strings.ToUpper(method)]; ok {
		return attr, orig
	}
	return semconv.HTTPRequestMethodGet, orig
}

func scheme(isTLS bool) attribute.KeyValue {
	if isTLS {
		return semconv.URLScheme("https")
	}
	return semconv.URLScheme("http")
}
