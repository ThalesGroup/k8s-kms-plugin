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

// Fatal logs an error message with optional key-value pairs and exits with status 1.
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
