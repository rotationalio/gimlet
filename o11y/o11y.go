package o11y

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

var (
	setup    sync.Once
	setupErr error
)

func Metrics(service string) (_ gin.HandlerFunc, err error) {
	if err = Setup(); err != nil {
		return nil, err
	}

	return func(c *gin.Context) {
		// Before request
		start := time.Now()

		// Handle the request
		c.Next()

		// After request
		status := strconv.Itoa(c.Writer.Status())
		method := c.Request.Method
		path := c.Request.URL.Path
		duration := time.Since(start)

		RequestsHandled.WithLabelValues(service, method, status, path).Inc()
		RequestDuration.WithLabelValues(service, method, status, path).Observe(duration.Seconds())
		RequestSize.WithLabelValues(service, method, status, path).Observe(float64(c.Request.ContentLength))
		ResponseSize.WithLabelValues(service, method, status, path).Observe(float64(c.Writer.Size()))
	}, nil
}

func Routes(router *gin.Engine) {
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))
}

func Setup() error {
	setup.Do(func() {
		// Register the collectors
		setupErr = initCollectors()
	})
	return setupErr
}

func initCollectors() (err error) {
	// Track all collectors to register at the end of the function.
	// When adding new collectors make sure to increase the capacity.
	collectors := make([]prometheus.Collector, 0, 4)

	var httpCollectors []prometheus.Collector
	if httpCollectors, err = initHTTPCollectors(); err != nil {
		return err
	}
	collectors = append(collectors, httpCollectors...)

	// Register the collectors
	registerCollectors(collectors)
	return nil
}

func registerCollectors(collectors []prometheus.Collector) {
	var err error
	// Register the collectors
	for _, collector := range collectors {
		if err = prometheus.Register(collector); err != nil {
			err = fmt.Errorf("cannot register collector of type %T: %w", collector, err)
			log.Warn().Err(err).Msg("collector already registered")
		}
	}
}
