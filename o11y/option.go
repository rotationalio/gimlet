package o11y

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Option configures the instrumentation middleware using functional variadic params.
type Option interface {
	apply(*config)
}

// Filter determines whether a given http.request should be traced. The filter must
// return true if the request should be traced.
type Filter func(*http.Request) bool

// GinFilter filters an http request based on the gin.Context. The filter must return
// true if the reuqest should be traced.
type GinFilter func(c *gin.Context) bool

// SpanNameFormatter customizes the request's span name.
type SpanNameFormatter func(c *gin.Context) string

// MetricAttributeFn is used to extract additional attributes from the http.Request and
// return them as a slice of attribute.KeyValue.
type MetricAttributeFn func(*http.Request) []attribute.KeyValue

// GinMetricAttributeFn is used to extract additional attributes from the gin.Context
// and return them as a slice of attribute.KeyValue.
type GinMetricAttributeFn func(c *gin.Context) []attribute.KeyValue

// Configuration settings for the instrumentation middleware.
type config struct {
	TracerProvider       trace.TracerProvider
	Propagators          propagation.TextMapPropagator
	SpanStartOptions     []trace.SpanStartOption
	Filters              []Filter
	GinFilters           []GinFilter
	SpanNameFormatter    SpanNameFormatter
	MeterProvider        metric.MeterProvider
	MetricAttributeFn    MetricAttributeFn
	GinMetricAttributeFn GinMetricAttributeFn
}

type optionFunc func(*config)

func (f optionFunc) apply(cfg *config) {
	f(cfg)
}

// WithPropagators specifies propagators to use for extracting
// information from the HTTP requests. If none are specified, global
// ones will be used.
func WithPropagators(propagators propagation.TextMapPropagator) Option {
	return optionFunc(func(cfg *config) {
		if propagators != nil {
			cfg.Propagators = propagators
		}
	})
}

// WithSpanStartOptions configures an additional set of
// trace.SpanStartOptions, which are applied to each new span.
func WithSpanStartOptions(opts ...trace.SpanStartOption) Option {
	return optionFunc(func(c *config) {
		c.SpanStartOptions = append(c.SpanStartOptions, opts...)
	})
}

// WithTracerProvider specifies a tracer provider to use for creating a tracer.
// If none is specified, the global provider is used.
func WithTracerProvider(provider trace.TracerProvider) Option {
	return optionFunc(func(cfg *config) {
		if provider != nil {
			cfg.TracerProvider = provider
		}
	})
}

// WithFilter adds a filter to the list of filters used by the handler.
// If any filter indicates to exclude a request then the request will not be
// traced. All gin and net/http filters must allow a request to be traced for a Span to be created.
// If no filters are provided then all requests are traced.
// Filters will be invoked for each processed request, it is advised to make them
// simple and fast.
func WithFilter(f ...Filter) Option {
	return optionFunc(func(c *config) {
		c.Filters = append(c.Filters, f...)
	})
}

// WithGinFilter adds a gin filter to the list of filters used by the handler.
func WithGinFilter(f ...GinFilter) Option {
	return optionFunc(func(c *config) {
		c.GinFilters = append(c.GinFilters, f...)
	})
}

// WithSpanNameFormatter takes a function that will be called on every
// request and the returned string will become the Span Name.
func WithSpanNameFormatter(f SpanNameFormatter) Option {
	return optionFunc(func(c *config) {
		c.SpanNameFormatter = f
	})
}

// WithMeterProvider specifies a meter provider to use for creating a meter.
// If none is specified, the global provider is used.
func WithMeterProvider(mp metric.MeterProvider) Option {
	return optionFunc(func(c *config) {
		c.MeterProvider = mp
	})
}

// WithMetricAttributeFn specifies a function that extracts additional attributes from the http.Request
// and returns them as a slice of attribute.KeyValue.
//
// If attributes are duplicated between this method and `WithGinMetricAttributeFn`, the attributes in this method will be overridden.
func WithMetricAttributeFn(f MetricAttributeFn) Option {
	return optionFunc(func(c *config) {
		c.MetricAttributeFn = f
	})
}

// WithGinMetricAttributeFn specifies a function that extracts additional attributes from the gin.Context
// and returns them as a slice of attribute.KeyValue.
//
// If attributes are duplicated between this method and `WithMetricAttributeFn`, the attributes in this method will be used.
func WithGinMetricAttributeFn(f GinMetricAttributeFn) Option {
	return optionFunc(func(c *config) {
		c.GinMetricAttributeFn = f
	})
}

//===========================================================================
// Default Configuration
//===========================================================================

func configure(opts ...Option) config {
	cfg := config{}
	for _, opt := range opts {
		opt.apply(&cfg)
	}

	if cfg.TracerProvider == nil {
		cfg.TracerProvider = otel.GetTracerProvider()
	}

	if cfg.Propagators == nil {
		cfg.Propagators = otel.GetTextMapPropagator()
	}

	if cfg.MeterProvider == nil {
		cfg.MeterProvider = otel.GetMeterProvider()
	}

	if cfg.SpanNameFormatter == nil {
		cfg.SpanNameFormatter = defaultSpanNameFormatter
	}

	return cfg
}

var defaultSpanNameFormatter SpanNameFormatter = func(c *gin.Context) string {
	method := strings.ToUpper(c.Request.Method)
	if !slices.Contains([]string{
		http.MethodGet, http.MethodHead,
		http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete,
		http.MethodConnect, http.MethodOptions,
		http.MethodTrace,
	}, method) {
		method = "HTTP"
	}

	if path := c.FullPath(); path != "" {
		return method + " " + path
	}

	return method
}
