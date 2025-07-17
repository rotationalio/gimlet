package logger

import (
	"encoding/json"
	"io"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	mu   sync.Mutex
	orig *zerolog.Logger
)

func ResetLogger() {
	mu.Lock()
	defer mu.Unlock()
	if orig != nil {
		log.Logger = *orig
	}
}

func Testing(tb testing.TB) {
	mu.Lock()
	defer mu.Unlock()
	orig = &log.Logger
	log.Logger = log.Output(zerolog.NewTestWriter(tb))
}

func Discard() {
	mu.Lock()
	defer mu.Unlock()
	orig = &log.Logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: io.Discard})
}

func TestSink() *Sink {
	mu.Lock()
	defer mu.Unlock()
	orig = &log.Logger
	sink := &Sink{}
	log.Logger = log.Output(sink)
	return sink
}

// A Sink is a custom io.Writer that can be used to capture log output and test it.
type Sink struct {
	sync.RWMutex
	logs []string
}

func (s *Sink) Write(p []byte) (n int, err error) {
	s.Lock()
	defer s.Unlock()
	s.logs = append(s.logs, string(p))
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
