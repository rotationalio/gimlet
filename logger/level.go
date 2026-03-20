package logger

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// LevelDecoder deserializes the log level from a config string.
// String names (panic, fatal, error, warn, info, debug, trace) map to slog.Level
// as follows: trace/debug → LevelDebug, info → LevelInfo, warn → LevelWarn,
// error/fatal/panic → LevelError.
type LevelDecoder slog.Level

// Names of log levels for use in encoding/decoding from strings.
const (
	llPanic = "panic"
	llFatal = "fatal"
	llError = "error"
	llWarn  = "warn"
	llInfo  = "info"
	llDebug = "debug"
	llTrace = "trace"
)

// Decode implements confire Decoder interface.
func (ll *LevelDecoder) Decode(value string) error {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case llPanic, llFatal, llError:
		*ll = LevelDecoder(slog.LevelError)
	case llWarn:
		*ll = LevelDecoder(slog.LevelWarn)
	case llInfo:
		*ll = LevelDecoder(slog.LevelInfo)
	case llDebug, llTrace:
		*ll = LevelDecoder(slog.LevelDebug)
	default:
		return fmt.Errorf("unknown log level %q", value)
	}
	return nil
}

// Level returns the slog.Level for use when setting handler level.
func (ll LevelDecoder) Level() slog.Level {
	return slog.Level(ll)
}

// Encode converts the log level into a string for use in YAML and JSON.
func (ll LevelDecoder) Encode() (string, error) {
	switch slog.Level(ll) {
	case slog.LevelError:
		return llError, nil
	case slog.LevelWarn:
		return llWarn, nil
	case slog.LevelInfo:
		return llInfo, nil
	case slog.LevelDebug:
		return llDebug, nil
	default:
		return "", fmt.Errorf("unknown log level %d", ll)
	}
}

func (ll LevelDecoder) String() string {
	ls, _ := ll.Encode()
	return ls
}

// UnmarshalJSON implements json.Unmarshaler
func (ll *LevelDecoder) UnmarshalJSON(data []byte) error {
	var ls string
	if err := json.Unmarshal(data, &ls); err != nil {
		return err
	}
	return ll.Decode(ls)
}

// MarshalJSON implements json.Marshaler
func (ll LevelDecoder) MarshalJSON() ([]byte, error) {
	ls, err := ll.Encode()
	if err != nil {
		return nil, err
	}
	return json.Marshal(ls)
}
