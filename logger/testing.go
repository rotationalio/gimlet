package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
)

var (
	mu   sync.Mutex
	orig *slog.Logger
)

//=============================================================================
// Public testing helpers
//=============================================================================

// ResetLogger restores the default slog logger saved by Testing, Discard, or TestSink.
func ResetLogger() {
	mu.Lock()
	defer mu.Unlock()
	if orig != nil {
		slog.SetDefault(orig)
		orig = nil
	}
}

// Testing sets slog's default logger to one that prints JSON lines via tb.Log.
func Testing(tb testing.TB) {
	mu.Lock()
	defer mu.Unlock()
	orig = slog.Default()
	slog.SetDefault(slog.New(&testHandler{tb: tb}))
}

// Discard discards all log output during testing.
func Discard() {
	mu.Lock()
	defer mu.Unlock()
	orig = slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

// TestSink sets the default logger to capture JSON lines in the returned Sink; call ResetLogger after.
func TestSink() *Sink {
	mu.Lock()
	defer mu.Unlock()
	orig = slog.Default()
	sink := &Sink{}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	slog.SetDefault(slog.New(slog.NewJSONHandler(sink, opts)))
	return sink
}

//=============================================================================
// Custom [slog.Handler] for testing
//=============================================================================

// NewTestHandler creates a new test handler that writes logs to the given
// [testing.TB].
func NewTestHandler(tb testing.TB) slog.Handler {
	return &testHandler{tb: tb}
}

// testHandler formats logs as JSON and sends one line per record to tb.Log.
// topAttrs: WithAttrs before any WithGroup. segments: each group and its scoped attrs.
type testHandler struct {
	tb       testing.TB
	topAttrs []slog.Attr
	segments []groupSegment
}

// groupSegment is one WithGroup plus the attrs added before the next WithGroup.
type groupSegment struct {
	name  string
	attrs []slog.Attr
}

// Enabled always returns true to accept all log levels during testing.
func (h *testHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *testHandler) Handle(ctx context.Context, r slog.Record) error {
	var buf bytes.Buffer
	var jh slog.Handler = slog.NewJSONHandler(&buf, nil)

	// topAttrs on the handler, not on r, so they stay top-level JSON keys.
	if len(h.topAttrs) > 0 {
		jh = jh.WithAttrs(h.topAttrs)
	}

	// Apply each group segment in order.
	for _, seg := range h.segments {
		jh = jh.WithGroup(seg.name)
		if len(seg.attrs) > 0 {
			jh = jh.WithAttrs(seg.attrs)
		}
	}

	_ = jh.Handle(ctx, r)
	h.tb.Log(buf.String())
	return nil
}

// WithAttrs adds attrs to topAttrs if no group is open; otherwise to the innermost segment.
func (h *testHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}

	// No groups open, add to topAttrs.
	if len(h.segments) == 0 {
		topAttrs := h.topAttrs
		if len(topAttrs) > 0 {
			topAttrs = append(slices.Clone(topAttrs), attrs...)
		} else {
			topAttrs = attrs
		}
		return &testHandler{tb: h.tb, topAttrs: topAttrs, segments: h.segments}
	}

	// At least one group open, add to the innermost segment.
	segs := slices.Clone(h.segments)
	last := len(segs) - 1
	if len(segs[last].attrs) > 0 {
		segs[last].attrs = append(slices.Clone(segs[last].attrs), attrs...)
	} else {
		segs[last].attrs = attrs
	}

	return &testHandler{tb: h.tb, topAttrs: h.topAttrs, segments: segs}
}

// WithGroup opens a new nested group; following WithAttrs attach to it until the next WithGroup.
func (h *testHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	segs := append(slices.Clone(h.segments), groupSegment{name: name})
	return &testHandler{tb: h.tb, topAttrs: h.topAttrs, segments: segs}
}

//=============================================================================
// Sink for capturing log output
//=============================================================================

// Sink is an io.Writer that captures log output (one JSON object per line) for tests.
type Sink struct {
	sync.RWMutex
	logs []string
}

func (s *Sink) Write(p []byte) (n int, err error) {
	s.Lock()
	defer s.Unlock()
	s.logs = append(s.logs, strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

func (s *Sink) Logs() []string {
	s.RLock()
	defer s.RUnlock()
	logs := make([]string, len(s.logs))
	copy(logs, s.logs)
	return logs
}

func (s *Sink) Reset() {
	s.Lock()
	defer s.Unlock()
	s.logs = nil
}

func (s *Sink) Index(i int) string {
	s.RLock()
	defer s.RUnlock()
	if i < 0 || i >= len(s.logs) {
		return ""
	}
	return s.logs[i]
}

func (s *Sink) Get(i int) map[string]interface{} {
	s.RLock()
	defer s.RUnlock()
	if i < 0 || i >= len(s.logs) {
		return nil
	}
	var logData map[string]interface{}
	if err := json.Unmarshal([]byte(s.logs[i]), &logData); err != nil {
		return nil
	}
	return logData
}
