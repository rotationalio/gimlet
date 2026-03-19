package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestTestHandler_GroupSegments checks that each group keeps its own WithAttrs
// (same shape as slog.With(...).WithGroup("foo").With(...).WithGroup("bar").With(...)).
func TestTestHandler_GroupSegments(t *testing.T) {
	tb := &captureTB{T: t}
	h := &testHandler{tb: tb}

	var jh slog.Handler = h

	// Top-level attr (no group yet).
	jh = jh.WithAttrs([]slog.Attr{slog.Int("top", 1)})

	// Open group "foo"; next WithAttrs will belong to foo.
	jh = jh.WithGroup("foo")
	jh = jh.WithAttrs([]slog.Attr{slog.Int("a", 2)})

	// Open nested group "bar" under foo; next WithAttrs belong to bar.
	jh = jh.WithGroup("bar")
	jh = jh.WithAttrs([]slog.Attr{slog.Int("b", 3)})

	// Group with no attrs.
	jh = jh.WithGroup("baz")

	// Do the log call.
	r := slog.NewRecord(time.Unix(0, 0).UTC(), slog.LevelInfo, "msg", 0)
	_ = jh.Handle(context.Background(), r)
	require.Len(t, tb.lines, 1)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(tb.lines[0]), &m))

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

// captureTB satisfies testing.TB via embedding *testing.T and records Log output.
type captureTB struct {
	*testing.T
	lines []string
}

func (c *captureTB) Log(args ...any) {
	c.lines = append(c.lines, strings.TrimSpace(fmt.Sprint(args...)))
}
