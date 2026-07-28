// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

// These tests cover the two PIN input methods added alongside the interactive
// prompt feature: the non-interactive error path (subprocess stdin is
// /dev/null — not a terminal) and the interactive PTY path where the test
// writes the PIN to the master side of a pseudo-terminal.

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/creack/pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThalesGroup/k8s-kms-plugin/pkg/providers"
)

// TestPIN_MissingNonInteractive confirms that the plugin exits immediately with
// a clear, actionable error when --p11-pin is omitted and stdin is not a
// terminal (the default when a subprocess is launched with nil Stdin →
// /dev/null).
func TestPIN_MissingNonInteractive(t *testing.T) {
	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pluginBin,
		"serve",
		"--socket", sock,
		"--p11-lib", testConfig.Path,
		"--p11-label", testConfig.TokenLabel,
		// --p11-pin intentionally omitted
		"--p11-key-label", "irrelevant", // satisfies cobra's MarkFlagsOneRequired
		"--algorithm-family", string(providers.AlgAESGCM),
		"--log-level", "error", // silence info/version noise
	)
	// Stdin is nil → /dev/null → term.IsTerminal returns false in the subprocess.
	out, err := cmd.CombinedOutput()

	require.Error(t, err, "plugin must exit non-zero when PIN is missing in non-interactive mode")
	outStr := string(out)
	assert.Contains(t, outStr, "--p11-pin", "error must name the missing flag")
	assert.Contains(t, outStr, "not a terminal", "error must explain the reason")
	t.Logf("plugin output:\n%s", outStr)
}

// TestPIN_InteractivePrompt verifies the full interactive PIN-via-prompt path
// end-to-end. A pseudo-terminal (PTY) pair is created so that the subprocess's
// stdin looks like a real terminal to term.IsTerminal. The test writes the PIN
// to the master side immediately after launch; the PTY kernel buffer holds the
// bytes until the subprocess calls term.ReadPassword.
func TestPIN_InteractivePrompt(t *testing.T) {
	label := newLabel(t)
	key, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(label), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate AES-256-GCM key")
	t.Cleanup(func() { _ = key.Delete() })

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	// Open a PTY pair. ptm is the master (test writes PIN here).
	// pts is the slave (subprocess reads PIN from here via its stdin fd).
	ptm, pts, err := pty.Open()
	if err != nil {
		t.Skipf("cannot open PTY — skipping interactive-prompt test: %v", err)
	}
	// Keep ptm open until the subprocess exits; closing it early would send
	// SIGHUP to the subprocess via the PTY hangup mechanism.
	defer ptm.Close()

	logPath := sock + ".log"
	logFile, ferr := os.Create(logPath)
	require.NoError(t, ferr)
	t.Cleanup(func() {
		logFile.Close()
		if data, rerr := os.ReadFile(logPath); rerr == nil && len(data) > 0 {
			t.Logf("=== plugin log ===\n%s", string(data))
		}
		os.Remove(logPath)
	})

	ctx, cancel := context.WithTimeout(context.Background(), pluginTestTimeout)

	cmd := exec.CommandContext(ctx, pluginBin,
		"serve",
		"--socket", sock,
		"--p11-lib", testConfig.Path,
		"--p11-label", testConfig.TokenLabel,
		// --p11-pin intentionally omitted — entered interactively via PTY
		"--p11-key-label", label,
		"--algorithm-family", string(providers.AlgAESGCM),
		"--log-level", "debug",
	)
	cmd.Stdin = pts // subprocess stdin is the slave PTY — term.IsTerminal returns true
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	require.NoError(t, cmd.Start())
	pts.Close() // parent no longer needs its copy; subprocess inherited its own fd

	proc := &pluginProcess{cmd: cmd, cancel: cancel}
	defer proc.stop()

	// Write the PIN to the master. The PTY line discipline buffers it; the
	// subprocess drains the buffer when term.ReadPassword is called.
	// A trailing newline terminates the read.
	_, err = fmt.Fprintln(ptm, testConfig.Pin)
	require.NoError(t, err, "write PIN to PTY master")

	waitForSocket(t, sock)
	kmsRoundtrip(t, sock)
}
