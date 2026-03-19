package logger_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"testing/slogtest"
	"time"

	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/logger"
)

// TestTestHandler runs the standard library slog conformance suite against testHandler.
func TestTestHandler(t *testing.T) {
	tb := &logCaptureTB{T: t, sink: logger.TestSink()}
	defer logger.ResetLogger()
	h := logger.NewTestHandler(tb)

	results := func() []map[string]any {
		out := make([]map[string]any, 0, len(tb.sink.Logs()))
		for _, log := range tb.sink.Logs() {
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(log), &m))
			out = append(out, m)
		}
		return out
	}

	err := slogtest.TestHandler(h, results)
	require.NoError(t, err)
}

// TestTestHandler_GroupSegments checks that each group keeps its own WithAttrs
// (same shape as slog.With(...).WithGroup("foo").With(...).WithGroup("bar").With(...)).
func TestTestHandler_GroupSegments(t *testing.T) {
	tb := &logCaptureTB{T: t, sink: logger.TestSink()}
	defer logger.ResetLogger()

	h := logger.NewTestHandler(tb)

	// Top-level attr (no group yet).
	h = h.WithAttrs([]slog.Attr{slog.Int("top", 1)})

	// Open group "foo"; next WithAttrs will belong to foo.
	h = h.WithGroup("foo")
	h = h.WithAttrs([]slog.Attr{slog.Int("a", 2)})

	// Open nested group "bar" under foo; next WithAttrs belong to bar.
	h = h.WithGroup("bar")
	h = h.WithAttrs([]slog.Attr{slog.Int("b", 3)})

	// Group with no attrs.
	h = h.WithGroup("baz")

	// Do the log call.
	r := slog.NewRecord(time.Unix(0, 0).UTC(), slog.LevelInfo, "msg", 0)
	_ = h.Handle(context.Background(), r)
	require.Len(t, tb.sink.Logs(), 1)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(tb.sink.Logs()[0]), &m))

	// "top" should be a root JSON key
	require.Equal(t, float64(1), m["top"])

	// "a" should live under the foo object
	foo, ok := m["foo"].(map[string]any)
	require.True(t, ok, "foo should be an object, got %T", m["foo"])
	require.Equal(t, float64(2), foo["a"])

	// "b" should be under foo.bar
	bar, ok := foo["bar"].(map[string]any)
	require.True(t, ok, "foo.bar should be an object, got %T", foo["bar"])
	require.Equal(t, float64(3), bar["b"])

	// "baz" should not be present under foo.bar
	_, hasBazBar := bar["baz"]
	require.False(t, hasBazBar, "baz should not be a nested key under foo.bar")

	// "baz" should not be present at root
	_, hasBazRoot := m["baz"]
	require.False(t, hasBazRoot, "baz should not be a root key")
}

// logCaptureTB satisfies [testing.TB] via embedding [testing.T] and records Log
// output using a [logger.Sink].
type logCaptureTB struct {
	*testing.T
	sink *logger.Sink
}

func (c *logCaptureTB) Log(args ...any) {
	c.sink.Write([]byte(strings.TrimSpace(fmt.Sprint(args...))))
}
