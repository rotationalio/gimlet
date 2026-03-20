package logger_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"go.rtnl.ai/gimlet/logger"

	"github.com/stretchr/testify/require"
)

func TestLevelDecoder(t *testing.T) {
	testTable := []struct {
		value    string
		expected slog.Level
	}{
		{"panic", slog.LevelError},
		{"FATAL", slog.LevelError},
		{"Error", slog.LevelError},
		{"   warn   ", slog.LevelWarn},
		{"iNFo", slog.LevelInfo},
		{"debug", slog.LevelDebug},
		{"trace", slog.LevelDebug},
	}

	// Test valid cases
	for _, testCase := range testTable {
		var level logger.LevelDecoder
		err := level.Decode(testCase.value)
		require.NoError(t, err)
		require.Equal(t, testCase.expected, level.Level())
	}

	// Test error case
	var level logger.LevelDecoder
	err := level.Decode("notalevel")
	require.EqualError(t, err, `unknown log level "notalevel"`)
}

func TestUnmarshaler(t *testing.T) {
	type Config struct {
		Level logger.LevelDecoder
	}

	var jsonConf Config
	err := json.Unmarshal([]byte(`{"level": "panic"}`), &jsonConf)
	require.NoError(t, err, "could not unmarshal level decoder in json file")
	require.Equal(t, slog.LevelError, jsonConf.Level.Level())
}

func TestMarshaler(t *testing.T) {
	confs := []struct {
		Level logger.LevelDecoder `yaml:"level" json:"level"`
	}{
		{logger.LevelDecoder(slog.LevelError)},
		{logger.LevelDecoder(slog.LevelWarn)},
		{logger.LevelDecoder(slog.LevelInfo)},
		{logger.LevelDecoder(slog.LevelDebug)},
	}

	for _, conf := range confs {
		data, err := json.Marshal(conf)
		require.NoError(t, err, "could not marshal data into json")
		require.Equal(t, []byte(fmt.Sprintf(`{"level":%q}`, conf.Level.String())), data)
	}
}
