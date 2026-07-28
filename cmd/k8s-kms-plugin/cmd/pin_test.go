// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isTermFn/readPassFn stubs shared across tests.
var (
	neverTerminal  = func(int) bool { return false }
	alwaysTerminal = func(int) bool { return true }
	// panicRead asserts that readPassFn is never reached (e.g. when viper already has the value).
	panicRead = func(int) ([]byte, error) { panic("readPassFn must not be called") }
)

// TestResolvePin_ExplicitValue checks that an explicitly configured PIN is
// returned directly without prompting, regardless of terminal state.
func TestResolvePin_ExplicitValue(t *testing.T) {
	v := viper.New()
	v.Set("p11-pin", "secret123")

	pin, err := resolvePinWithFns(v, "p11-pin", "Enter PIN: ", neverTerminal, panicRead)

	require.NoError(t, err)
	assert.Equal(t, "secret123", pin)
}

// TestResolvePin_ExplicitEmptyValue covers no-PIN tokens
// (CKF_PROTECTED_AUTHENTICATION_PATH or tokens that accept an empty string).
// An explicitly configured empty string must be returned as-is without prompting.
func TestResolvePin_ExplicitEmptyValue(t *testing.T) {
	v := viper.New()
	v.Set("p11-pin", "")

	pin, err := resolvePinWithFns(v, "p11-pin", "Enter PIN: ", neverTerminal, panicRead)

	require.NoError(t, err)
	assert.Equal(t, "", pin)
}

// TestResolvePin_NonInteractiveNoConfig verifies that a missing PIN in a
// non-interactive environment (CI, containers, scripts) returns an actionable
// error that names the missing flag.
func TestResolvePin_NonInteractiveNoConfig(t *testing.T) {
	v := viper.New()

	_, err := resolvePinWithFns(v, "p11-pin", "Enter PIN: ", neverTerminal, panicRead)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--p11-pin")
	assert.Contains(t, err.Error(), "not a terminal")
}

// TestResolvePin_NonInteractiveErrorMentionsKey checks that the error names the
// exact key — useful because both --p11-pin and --old-p11-pin go through this path.
func TestResolvePin_NonInteractiveErrorMentionsKey(t *testing.T) {
	v := viper.New()

	_, err := resolvePinWithFns(v, "old-p11-pin", "Enter old PIN: ", neverTerminal, panicRead)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--old-p11-pin")
}

// TestResolvePin_InteractivePrompt simulates a user typing their PIN at the
// terminal. The mock readPassFn replaces term.ReadPassword so no real PTY is
// needed in unit tests.
func TestResolvePin_InteractivePrompt(t *testing.T) {
	v := viper.New()
	wantPin := "myInteractivePin"
	fakeRead := func(int) ([]byte, error) { return []byte(wantPin), nil }

	pin, err := resolvePinWithFns(v, "p11-pin", "Enter PIN: ", alwaysTerminal, fakeRead)

	require.NoError(t, err)
	assert.Equal(t, wantPin, pin)
}

// TestResolvePin_InteractivePromptEmpty covers pressing Enter without a PIN —
// valid for no-PIN tokens discovered interactively at runtime.
func TestResolvePin_InteractivePromptEmpty(t *testing.T) {
	v := viper.New()
	fakeRead := func(int) ([]byte, error) { return []byte(""), nil }

	pin, err := resolvePinWithFns(v, "p11-pin", "Enter PIN: ", alwaysTerminal, fakeRead)

	require.NoError(t, err)
	assert.Equal(t, "", pin)
}

// TestResolvePin_ReadError verifies that a terminal I/O error is wrapped with
// the flag name so the caller can log a useful diagnostic message.
func TestResolvePin_ReadError(t *testing.T) {
	v := viper.New()
	termErr := errors.New("terminal read failed")
	fakeRead := func(int) ([]byte, error) { return nil, termErr }

	_, err := resolvePinWithFns(v, "p11-pin", "Enter PIN: ", alwaysTerminal, fakeRead)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading PIN for --p11-pin")
	assert.ErrorIs(t, err, termErr)
}
