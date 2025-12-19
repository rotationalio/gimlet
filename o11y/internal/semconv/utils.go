package semconv

import "go.opentelemetry.io/otel"

func handleErr(err error) {
	if err != nil {
		otel.Handle(err)
	}
}
