package o11y_test

import (
	"context"
	"errors"
	"html/template"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	stdout "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.rtnl.ai/gimlet/o11y"
)

var tracer = otel.Tracer("o11y")

func Example() {
	var (
		err error
		tp  *trace.TracerProvider
	)

	if tp, err = initTracer(); err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Printf("error shutting down tracer provider: %v", err)
		}
	}()

	router := gin.New()
	router.Use(o11y.Middleware("myservice"))

	tmpl := template.Must(template.New("userDetail").Parse(`
		<html>
			<body>
				<h1>User Detail</h1>
				<p>User Name: {{.Name }}</p>
				<p>User ID: {{.ID }}</p>
			</body>
		</html>
	`))

	router.SetHTMLTemplate(tmpl)

	router.GET("/users/:id", func(c *gin.Context) {
		userID := c.Param("id")
		name := getUser(c, userID)
		c.HTML(http.StatusOK, "userDetail", gin.H{
			"Name": name,
			"ID":   userID,
		})
	})

	_ = router.Run(":8080")
}

func initTracer() (tp *trace.TracerProvider, err error) {
	var exporter trace.SpanExporter
	if exporter, err = stdout.New(stdout.WithPrettyPrint()); err != nil {
		return nil, err
	}

	tp = trace.NewTracerProvider(
		trace.WithSampler(trace.AlwaysSample()),
		trace.WithBatcher(exporter),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{},
		),
	)

	return tp, nil
}

func getUser(c *gin.Context, userID string) string {
	// Pass the built-in `context.Context` object from http.Request to OpenTelemetry APIs
	// where required. It is available from gin.Context.Request.Context()
	_, span := tracer.Start(c.Request.Context(), "getUser", oteltrace.WithAttributes(attribute.String("userID", userID)))
	defer span.End()

	if userID == "123" {
		return "Jane Pershing"
	}

	c.Error(errors.New("user not found"))
	return "unknown"
}
