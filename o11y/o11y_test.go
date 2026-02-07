package o11y_test

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/gimlet/o11y"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestNotInstrumented(t *testing.T) {
	router := gin.New()
	router.GET("/", func(c *gin.Context) {
		// Assert we don't have a span on the context.
		span := trace.SpanFromContext(c.Request.Context())
		assert.False(t, span.SpanContext().IsValid(), "expected no valid span on the context")
		_, _ = c.Writer.WriteString("ok")
	})

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPropagation(t *testing.T) {
	t.Run("GlobalPropagators", func(t *testing.T) {
		provider := noop.NewTracerProvider()
		otel.SetTextMapPropagator(b3.New())

		r := httptest.NewRequest(http.MethodGet, "/user/42", http.NoBody)
		w := httptest.NewRecorder()

		ctx := t.Context()
		sc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{0x01},
			SpanID:  trace.SpanID{0x01},
		})

		ctx = trace.ContextWithRemoteSpanContext(ctx, sc)
		ctx, _ = provider.Tracer(o11y.ScopeName).Start(ctx, "test")
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(r.Header))

		router := gin.New()
		router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider)))
		router.GET("/user/:id", func(c *gin.Context) {
			span := trace.SpanFromContext(c.Request.Context())
			assert.Equal(t, sc.TraceID(), span.SpanContext().TraceID())
			assert.Equal(t, sc.SpanID(), span.SpanContext().SpanID())
		})

		router.ServeHTTP(w, r)
	})

	t.Run("CustomPropagators", func(t *testing.T) {
		provider := noop.NewTracerProvider()
		b3p := b3.New()

		r := httptest.NewRequest(http.MethodGet, "/user/42", http.NoBody)
		w := httptest.NewRecorder()

		ctx := t.Context()
		sc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{0x01},
			SpanID:  trace.SpanID{0x01},
		})

		ctx = trace.ContextWithRemoteSpanContext(ctx, sc)
		ctx, _ = provider.Tracer(o11y.ScopeName).Start(ctx, "test")
		b3p.Inject(ctx, propagation.HeaderCarrier(r.Header))

		router := gin.New()
		router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider)))
		router.GET("/user/:id", func(c *gin.Context) {
			span := trace.SpanFromContext(c.Request.Context())
			assert.Equal(t, sc.TraceID(), span.SpanContext().TraceID())
			assert.Equal(t, sc.SpanID(), span.SpanContext().SpanID())
		})

		router.ServeHTTP(w, r)
	})

}

func TestChildSpan(t *testing.T) {
	t.Run("GlobalTracer", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		otel.SetTracerProvider(sdk.NewTracerProvider(sdk.WithSpanProcessor(sr)))

		router := gin.New()
		router.Use(o11y.Middleware("example"))
		router.GET("/user/:id", func(*gin.Context) {})

		r := httptest.NewRequest(http.MethodGet, "/user/42", http.NoBody)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)
		assert.Len(t, sr.Ended(), 1)
	})

	t.Run("CustomTracer", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(sr))

		router := gin.New()
		router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider)))
		router.GET("/user/:id", func(*gin.Context) {})

		r := httptest.NewRequest(http.MethodGet, "/user/42", http.NoBody)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)
		assert.Len(t, sr.Ended(), 1)
	})
}

func TestTrace(t *testing.T) {
	t.Run("Ok", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(sr))

		router := gin.New()
		router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider)))
		router.GET("/user/:id", func(c *gin.Context) {
			userID := c.Param("id")
			c.Writer.WriteString(userID)
		})

		r := httptest.NewRequest(http.MethodGet, "/user/42", http.NoBody)
		w := httptest.NewRecorder()

		// execute and verify the request
		router.ServeHTTP(w, r)
		rep := w.Result()
		require.Equal(t, http.StatusOK, rep.StatusCode)

		// verify the traces
		spans := sr.Ended()
		require.Len(t, spans, 1)

		span := spans[0]
		assert.Equal(t, "GET /user/:id", span.Name())
		assert.Equal(t, trace.SpanKindServer, span.SpanKind())

		attrs := span.Attributes()
		assert.Contains(t, attrs, attribute.String("server.address", "example"))
		assert.Contains(t, attrs, attribute.Int("http.response.status_code", http.StatusOK))
		assert.Contains(t, attrs, attribute.String("http.request.method", "GET"))
		assert.Contains(t, attrs, attribute.String("http.route", "/user/:id"))
		assert.Empty(t, span.Events())
		assert.Equal(t, codes.Unset, span.Status().Code)
		assert.Empty(t, span.Status().Description)
	})

	t.Run("Error", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(sr))

		router := gin.New()
		router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider)))
		router.POST("/register", func(c *gin.Context) {
			_ = c.Error(errors.New("something wicked"))
			_ = c.AbortWithError(http.StatusInsufficientStorage, errors.New("eye of newt"))
		})

		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer([]byte("foo")))
		w := httptest.NewRecorder()

		// execute and verify the request
		router.ServeHTTP(w, r)
		rep := w.Result()
		require.Equal(t, http.StatusInsufficientStorage, rep.StatusCode)

		// verify the traces
		spans := sr.Ended()
		require.Len(t, spans, 1)

		span := spans[0]
		assert.Equal(t, "POST /register", span.Name())

		attrs := span.Attributes()
		assert.Contains(t, attrs, attribute.String("server.address", "example"))
		assert.Contains(t, attrs, attribute.Int("http.response.status_code", http.StatusInsufficientStorage))

		events := span.Events()
		require.Len(t, events, 2)
		assert.Equal(t, "exception", events[0].Name)
		assert.Contains(t, events[0].Attributes, attribute.String("exception.type", "*errors.errorString"))
		assert.Contains(t, events[0].Attributes, attribute.String("exception.message", "something wicked"))

		assert.Equal(t, "exception", events[1].Name)
		assert.Contains(t, events[1].Attributes, attribute.String("exception.type", "*errors.errorString"))
		assert.Contains(t, events[1].Attributes, attribute.String("exception.message", "eye of newt"))
	})
}

func TestSpanStatus(t *testing.T) {
	tests := []struct {
		statusCode int
		spanStatus codes.Code
	}{
		{http.StatusOK, codes.Unset},
		{http.StatusBadRequest, codes.Unset},
		{http.StatusUnauthorized, codes.Unset},
		{http.StatusNotFound, codes.Unset},
		{http.StatusInternalServerError, codes.Error},
		{http.StatusServiceUnavailable, codes.Error},
		{http.StatusInsufficientStorage, codes.Error},
	}

	for _, tc := range tests {
		t.Run(strconv.Itoa(tc.statusCode), func(t *testing.T) {
			sr := tracetest.NewSpanRecorder()
			provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(sr))

			router := gin.New()
			router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider)))
			router.GET("/", func(c *gin.Context) {
				c.Status(tc.statusCode)
			})

			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, r)
			rep := w.Result()
			require.Equal(t, tc.statusCode, rep.StatusCode)

			require.Len(t, sr.Ended(), 1, "should emit a span")
			require.Equal(t, tc.spanStatus, sr.Ended()[0].Status().Code, "should only set error status for http 5xx error codes")
		})
	}

	t.Run("200WithError", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(sr))

		router := gin.New()
		router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider)))
		router.GET("/", func(c *gin.Context) {
			c.Error(errors.New("something wicked"))
			c.Status(http.StatusOK)
		})

		r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)
		rep := w.Result()
		require.Equal(t, http.StatusOK, rep.StatusCode)

		require.Len(t, sr.Ended(), 1, "should emit a span")
		require.Equal(t, codes.Error, sr.Ended()[0].Status().Code, "should set error status if errors are on the gin context")
		require.Len(t, sr.Ended()[0].Events(), 1)
		require.Contains(t, sr.Ended()[0].Events()[0].Attributes, attribute.String("exception.message", "something wicked"))
	})
}

func TestSpanOptions(t *testing.T) {
	t.Run("CustomAttributes", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(sr))

		customAttr := attribute.String("custom.key", "custom.value")

		router := gin.New()
		router.Use(o11y.Middleware("example",
			o11y.WithTracerProvider(provider),
			o11y.WithSpanStartOptions(trace.WithAttributes(customAttr)),
		))
		router.GET("/", func(c *gin.Context) {})

		r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		spans := sr.Ended()
		require.Len(t, spans, 1)
		require.Contains(t, spans[0].Attributes(), customAttr)
		require.Equal(t, trace.SpanKindServer, spans[0].SpanKind())
	})
}

func TestSpanName(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(sr))

	tests := []struct {
		method    string
		route     string
		path      string
		formatter o11y.SpanNameFormatter
		expected  string
	}{
		// Test for standard methods
		{http.MethodGet, "/user/:id", "/user/1", nil, "GET /user/:id"},
		{http.MethodPost, "/user/:id", "/user/1", nil, "POST /user/:id"},
		{http.MethodPut, "/user/:id", "/user/1", nil, "PUT /user/:id"},
		{http.MethodPatch, "/user/:id", "/user/1", nil, "PATCH /user/:id"},
		{http.MethodDelete, "/user/:id", "/user/1", nil, "DELETE /user/:id"},
		{http.MethodConnect, "/user/:id", "/user/1", nil, "CONNECT /user/:id"},
		{http.MethodOptions, "/user/:id", "/user/1", nil, "OPTIONS /user/:id"},
		{http.MethodTrace, "/user/:id", "/user/1", nil, "TRACE /user/:id"},

		// Test for no route
		{http.MethodGet, "", "/user/1", nil, "GET"},

		// Test for invalid method
		{"INVALID", "/user/:id", "/user/1", nil, "HTTP /user/:id"},

		// Test for custom span name formatter
		{http.MethodGet, "/user/:id", "/user/1", func(c *gin.Context) string { return c.Request.URL.Path }, "/user/1"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("method: %s, route: %s, path: %s", tc.method, tc.route, tc.path), func(t *testing.T) {
			defer sr.Reset()

			router := gin.New()
			router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider), o11y.WithSpanNameFormatter(tc.formatter)))
			router.Handle(tc.method, tc.route, func(c *gin.Context) {})

			r := httptest.NewRequest(tc.method, tc.path, http.NoBody)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			require.Len(t, sr.Ended(), 1, "should emit a span")
			require.Equal(t, tc.expected, sr.Ended()[0].Name(), "should use the custom formatter")
		})
	}
}

func TestFilter(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(sr))

	filter := func(r *http.Request) bool {
		return r.URL.Path != "/v1/status"
	}

	router := gin.New()
	router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider), o11y.WithFilter(filter)))
	router.GET("/v1/status", func(c *gin.Context) {})
	router.GET("/v1/users", func(c *gin.Context) {})

	t.Run("Filtered", func(t *testing.T) {
		defer sr.Reset()

		r := httptest.NewRequest(http.MethodGet, "/v1/status", http.NoBody)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Empty(t, sr.Ended(), "should not emit a span")
	})

	t.Run("NotFiltered", func(t *testing.T) {
		defer sr.Reset()

		r := httptest.NewRequest(http.MethodGet, "/v1/users", http.NoBody)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Len(t, sr.Ended(), 1, "should emit a span")
	})
}

func TestGinFilter(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(sr))

	filter := func(c *gin.Context) bool {
		return c.FullPath() != "/v1/status"
	}

	router := gin.New()
	router.Use(o11y.Middleware("example", o11y.WithTracerProvider(provider), o11y.WithGinFilter(filter)))
	router.GET("/v1/status", func(c *gin.Context) {})
	router.GET("/v1/users", func(c *gin.Context) {})

	t.Run("Filtered", func(t *testing.T) {
		defer sr.Reset()

		r := httptest.NewRequest(http.MethodGet, "/v1/status", http.NoBody)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Empty(t, sr.Ended(), "should not emit a span")
	})

	t.Run("NotFiltered", func(t *testing.T) {
		defer sr.Reset()

		r := httptest.NewRequest(http.MethodGet, "/v1/users", http.NoBody)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Len(t, sr.Ended(), 1, "should emit a span")
	})
}

func TestMetrics(t *testing.T) {
	tests := []struct {
		name           string
		extractor      func(*http.Request) []attribute.KeyValue
		ginExtractor   func(*gin.Context) []attribute.KeyValue
		target         string
		expectedRoute  string
		expectedStatus int64
	}{
		{
			name:           "Default",
			extractor:      nil,
			ginExtractor:   nil,
			target:         "/users/42",
			expectedRoute:  "/users/:id",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "NotFound",
			extractor:      nil,
			ginExtractor:   nil,
			target:         "/users/11",
			expectedRoute:  "/users/:id",
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "Callbacks",
			extractor: func(r *http.Request) []attribute.KeyValue {
				return []attribute.KeyValue{
					attribute.String("key1", "value1"),
					attribute.String("key2", "value2"),
					attribute.String("method", strings.ToUpper(r.Method)),
				}
			},
			ginExtractor: func(c *gin.Context) []attribute.KeyValue {
				return []attribute.KeyValue{
					attribute.String("key3", "value3"),
				}
			},
			target:         "/users/42",
			expectedRoute:  "/users/:id",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := metric.NewManualReader()
			provider := metric.NewMeterProvider(metric.WithReader(reader))

			router := gin.New()
			router.Use(o11y.Middleware("example",
				o11y.WithMeterProvider(provider),
				o11y.WithMetricAttributeFn(tc.extractor),
				o11y.WithGinMetricAttributeFn(tc.ginExtractor),
			))

			router.GET("/users/:id", func(c *gin.Context) {
				id := c.Param("id")
				if id != "42" {
					c.Status(http.StatusNotFound)
					return
				}
				c.Writer.WriteString(id)
			})

			r := httptest.NewRequest(http.MethodGet, tc.target, http.NoBody)
			w := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(w)
			c.Request = r
			router.ServeHTTP(w, r)

			// verify metrics
			rm := metricdata.ResourceMetrics{}
			require.NoError(t, reader.Collect(t.Context(), &rm))

			require.Len(t, rm.ScopeMetrics, 1)
			sm := rm.ScopeMetrics[0]
			require.Equal(t, o11y.ScopeName, sm.Scope.Name)
			require.Equal(t, gimlet.Version(), sm.Scope.Version)

			attrs := []attribute.KeyValue{
				attribute.String("http.request.method", "GET"),
				attribute.Int64("http.response.status_code", tc.expectedStatus),
				attribute.String("network.protocol.name", "http"),
				attribute.String("network.protocol.version", fmt.Sprintf("1.%d", r.ProtoMinor)),
				attribute.String("server.address", "example"),
				attribute.String("url.scheme", "http"),
			}

			if tc.expectedRoute != "" {
				attrs = append(attrs, attribute.String("http.route", tc.expectedRoute))
			}

			if tc.extractor != nil {
				attrs = append(attrs, tc.extractor(r)...)
			}

			if tc.ginExtractor != nil {
				attrs = append(attrs, tc.ginExtractor(c)...)
			}

			metricdatatest.AssertEqual(t, metricdata.Metrics{
				Name:        "http.server.request.body.size",
				Description: "Size of HTTP server request bodies.",
				Unit:        "By",
				Data: metricdata.Histogram[int64]{
					Temporality: metricdata.CumulativeTemporality,
					DataPoints: []metricdata.HistogramDataPoint[int64]{
						{
							Attributes: attribute.NewSet(attrs...),
						},
					},
				},
			}, sm.Metrics[0], metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreValue(), metricdatatest.IgnoreExemplars())

			metricdatatest.AssertEqual(t, metricdata.Metrics{
				Name:        "http.server.response.body.size",
				Description: "Size of HTTP server response bodies.",
				Unit:        "By",
				Data: metricdata.Histogram[int64]{
					Temporality: metricdata.CumulativeTemporality,
					DataPoints: []metricdata.HistogramDataPoint[int64]{
						{
							Attributes: attribute.NewSet(attrs...),
						},
					},
				},
			}, sm.Metrics[1], metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreValue(), metricdatatest.IgnoreExemplars())

			metricdatatest.AssertEqual(t, metricdata.Metrics{
				Name:        "http.server.request.duration",
				Description: "Duration of HTTP server requests.",
				Unit:        "s",
				Data: metricdata.Histogram[float64]{
					Temporality: metricdata.CumulativeTemporality,
					DataPoints: []metricdata.HistogramDataPoint[float64]{
						{
							Attributes: attribute.NewSet(attrs...),
						},
					},
				},
			}, sm.Metrics[2], metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreValue(), metricdatatest.IgnoreExemplars())

		})
	}
}
