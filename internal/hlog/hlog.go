// Package hlog emits structured lifecycle events.
//
// Container lifecycle logs are read by machines far more often than by people:
// the questions asked of them are "how many containers were OOM-killed in the
// last hour" and "what was the p99 time from create to running", neither of
// which is answerable by grepping prose. Every event is therefore one JSON
// object on one line, with a stable event name and typed fields.
//
// Human-facing output goes to stdout as plain text; this goes to stderr. Keeping
// them on separate streams is what lets `husk run` be used in a pipeline without
// the logs corrupting the container's output.
package hlog

import (
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	once   sync.Once
	logger *slog.Logger
)

// L returns the process logger, configuring it on first use. HUSK_LOG_LEVEL
// selects the threshold; HUSK_LOG_FORMAT=text swaps to a readable format for
// interactive debugging.
func L() *slog.Logger {
	once.Do(func() {
		level := slog.LevelInfo
		switch strings.ToLower(os.Getenv("HUSK_LOG_LEVEL")) {
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}

		opts := &slog.HandlerOptions{Level: level}
		var h slog.Handler = slog.NewJSONHandler(os.Stderr, opts)
		if strings.EqualFold(os.Getenv("HUSK_LOG_FORMAT"), "text") {
			h = slog.NewTextHandler(os.Stderr, opts)
		}
		logger = slog.New(h)
	})
	return logger
}

// Event records a lifecycle transition. The name is a fixed vocabulary —
// container.create, container.start, container.exit, container.delete — so a log
// pipeline can aggregate on it without parsing free text.
func Event(name, id string, attrs ...any) {
	L().Info(name, append([]any{slog.String("container", id)}, attrs...)...)
}

// Duration is the standard attribute for a measured phase, in milliseconds.
// Recorded as a number rather than a formatted string so it can be aggregated
// without a parsing step.
func Duration(key string, d time.Duration) slog.Attr {
	return slog.Float64(key+"_ms", float64(d.Nanoseconds())/1e6)
}
