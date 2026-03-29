package logger

import (
	"io"
	"log/slog"
	"sync"
	"testing"

	"go.rtnl.ai/x/rlog"
	rlogtest "go.rtnl.ai/x/rlog/testing"
)

var (
	mu        sync.Mutex
	orig      *rlog.Logger
	origLevel slog.Level
)

// ResetLogger restores the default rlog logger saved by Testing, Discard, or TestSink.
func ResetLogger() {
	mu.Lock()
	defer mu.Unlock()

	if orig != nil {
		rlog.SetDefault(orig)
		rlog.SetLevel(origLevel)
		orig = nil
	}
}

// Testing sets the default rlog logger to one that prints JSON lines via tb.Log
// during testing. Call [ResetLogger] when done.
func Testing(tb testing.TB) {
	mu.Lock()
	defer mu.Unlock()

	aCopy := *rlog.Default()
	orig = &aCopy
	origLevel = rlog.Level()

	h := rlogtest.NewCapturingTestHandler(tb)
	l := rlog.New(slog.New(h))
	rlog.SetDefault(l)
}

// Discard sets the default rlog logger to one that discards all log output
// during testing. Call [ResetLogger] when done.
func Discard() {
	mu.Lock()
	defer mu.Unlock()

	aCopy := *rlog.Default()
	orig = &aCopy
	origLevel = rlog.Level()

	opts := rlog.MergeWithCustomLevels(rlog.WithGlobalLevel(&slog.HandlerOptions{}))
	jsonh := slog.NewJSONHandler(io.Discard, opts)
	l := rlog.New(slog.New(jsonh))
	rlog.SetDefault(l)
}

// TestSink configures [rlog.Default] to log into a new [rlog.CapturingTestHandler]
// at debug level. Call [ResetLogger] when done.
func TestSink() *rlogtest.CapturingTestHandler {
	mu.Lock()
	defer mu.Unlock()

	aCopy := *rlog.Default()
	orig = &aCopy
	origLevel = rlog.Level()

	rlog.SetLevel(slog.LevelDebug)
	cap := rlogtest.NewCapturingTestHandler(nil)
	l := rlog.New(slog.New(cap))
	rlog.SetDefault(l)

	return cap
}
