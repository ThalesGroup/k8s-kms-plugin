/*
 * Copyright 2026 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package logging

import (
	"fmt"
	"log/slog"
	"math"
	"os"

	"github.com/lmittmann/tint"
)

// LevelTrace is a custom slog level below Debug, following the convention of slog.Level(-8).
const LevelTrace = slog.Level(-8)

// LevelQuiet suppresses all log output when used with a DiscardHandler.
// It is not passed to a handler's minimum level; instead root.go detects it
// and installs slog.DiscardHandler directly.
const LevelQuiet = slog.Level(math.MaxInt)

// ParseLevel converts a level name string to a slog.Level.
// Accepted values: trace, debug, info, warn, error, quiet.
func ParseLevel(s string) (slog.Level, error) {
	switch s {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	case "quiet":
		return LevelQuiet, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q, accepted: trace, debug, info, warn, error, quiet", s)
	}
}

// ReplaceAttr maps LevelTrace to the label "TRC" with cyan color (ANSI 36),
// making it visually distinct from DBG (no color) in tint text output.
// tint.Attr wraps the value in a slog.LogValuer so that slog.JSONHandler
// transparently unwraps it to a plain "TRC" string without color codes.
// Pass it as the ReplaceAttr field of both tint.Options and slog.HandlerOptions.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		if level, ok := a.Value.Any().(slog.Level); ok && level == LevelTrace {
			return tint.Attr(36, slog.String(slog.LevelKey, "TRC"))
		}
	}
	return a
}

// Fatal logs an error message with optional key-value pairs and exits with status 1.
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
