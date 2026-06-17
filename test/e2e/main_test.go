// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

// Package e2e exercises the k8s-kms-plugin binary end-to-end against an
// ephemeral SoftHSMv3 token, using grpcurl to drive the KMS v2 gRPC API.
//
// Required environment variables:
//
//	P11_LIBRARY   path to the PKCS#11 shared library
//	P11_PIN       user PIN (default: 1234)
//
// The k8s-kms-plugin binary must be built before running these tests:
//
//	make build
//	P11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so go test -v ./test/e2e/
//
// aes-gcm, aes-cbc and rsa-oaep work with SoftHSMv2 or SoftHSMv3.
// ml-kem requires SoftHSMv3: https://github.com/pqctoday-org/pqctoday-hsm
package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThalesGroup/crypto11"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// Package-level state initialised by TestMain and consumed by all tests.
var (
	testConfig *crypto11.Config
	testCtx    *crypto11.Context
	pluginBin  string // absolute path to the k8s-kms-plugin binary
	repoRoot   string // absolute path to the repository root
	protoFile  string // absolute path to scripts/grpcurl/api.proto
)

const (
	e2eTokenLabel = "e2e-test-token"
	e2eSoPin      = "0000"
	e2eDefaultPin = "1234"
)

// TestMain bootstraps an ephemeral SoftHSM token, verifies it, connects
// crypto11, locates the plugin binary, then runs all tests.
// Without P11_LIBRARY the whole suite is skipped cleanly.
func TestMain(m *testing.M) {
	lib := os.Getenv("P11_LIBRARY")
	if lib == "" {
		fmt.Fprintln(os.Stderr, "P11_LIBRARY not set — skipping e2e tests")
		os.Exit(0)
	}

	var err error
	// Working directory for test binaries is the package directory (test/e2e/).
	repoRoot, err = filepath.Abs("../..")
	if err != nil {
		panic("TestMain: filepath.Abs: " + err.Error())
	}
	protoFile = filepath.Join(repoRoot, "scripts", "grpcurl", "api.proto")
	if _, err := os.Stat(protoFile); err != nil {
		panic("TestMain: api.proto not found at " + protoFile)
	}

	pluginBin = findPluginBin(repoRoot)

	teardown := initSoftHSMToken(lib)
	verifySoftHSMToken(lib)
	initCrypto11()

	code := m.Run()

	shutdownCrypto11()
	teardown()
	os.Exit(code)
}

// findPluginBin looks for the k8s-kms-plugin binary at the repo root
// (where `make build` places it) and then falls back to PATH.
func findPluginBin(root string) string {
	candidate := filepath.Join(root, "k8s-kms-plugin")
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate
	}
	// Fallback to PATH.
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, "k8s-kms-plugin")
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	panic("k8s-kms-plugin binary not found in repo root or PATH — run 'make build' first")
}

// initSoftHSMToken creates a temporary directory, writes softhsm2.conf, and
// initialises a fresh PKCS#11 token using the raw pkcs11 API — identical
// pattern to test/integration/main_test.go.
func initSoftHSMToken(modulePath string) func() {
	dir, err := os.MkdirTemp("", "softhsm-e2e-*")
	if err != nil {
		panic("initSoftHSMToken: MkdirTemp: " + err.Error())
	}

	tokensDir := filepath.Join(dir, "tokens")
	if err := os.Mkdir(tokensDir, 0700); err != nil {
		panic("initSoftHSMToken: Mkdir(tokens): " + err.Error())
	}

	conf := filepath.Join(dir, "softhsm2.conf")
	content := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n",
		tokensDir,
	)
	if err := os.WriteFile(conf, []byte(content), 0600); err != nil {
		panic("initSoftHSMToken: WriteFile(softhsm2.conf): " + err.Error())
	}

	os.Setenv("SOFTHSM2_CONF", conf)

	if os.Getenv("P11_PIN") == "" {
		os.Setenv("P11_PIN", e2eDefaultPin)
	}
	userPin := os.Getenv("P11_PIN")

	ctx, err := pkcs11.New(modulePath)
	if err != nil {
		panic("initSoftHSMToken: failed to load P11_LIBRARY: " + modulePath + ": " + err.Error())
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		panic("initSoftHSMToken: C_Initialize: " + err.Error())
	}

	slots, err := ctx.GetSlotList(false)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		panic(fmt.Sprintf("initSoftHSMToken: C_GetSlotList(false): %v (slots=%d)", err, len(slots)))
	}

	if err := ctx.InitToken(slots[0], []byte(e2eSoPin), e2eTokenLabel); err != nil {
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: C_InitToken: " + err.Error())
	}

	slots, err = ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		panic(fmt.Sprintf("initSoftHSMToken: C_GetSlotList(true): %v (slots=%d)", err, len(slots)))
	}

	sh, err := ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: OpenSession: " + err.Error())
	}
	if err := ctx.Login(sh, pkcs11.CKU_SO, []byte(e2eSoPin)); err != nil {
		ctx.CloseSession(sh)
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: Login(SO): " + err.Error())
	}
	if err := ctx.InitPIN(sh, []byte(userPin)); err != nil {
		ctx.Logout(sh)
		ctx.CloseSession(sh)
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: C_InitPIN: " + err.Error())
	}
	ctx.Logout(sh)
	ctx.CloseSession(sh)
	ctx.Finalize()
	ctx.Destroy()

	os.Setenv("P11_TOKEN", e2eTokenLabel)
	fmt.Printf("initSoftHSMToken: token %q ready in %s\n", e2eTokenLabel, dir)

	return func() { os.RemoveAll(dir) }
}

// verifySoftHSMToken reopens the module and asserts the token is properly
// initialised and accepts a user login.
func verifySoftHSMToken(modulePath string) {
	ctx, err := pkcs11.New(modulePath)
	if err != nil {
		panic("verifySoftHSMToken: failed to load module " + modulePath + ": " + err.Error())
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		panic("verifySoftHSMToken: C_Initialize: " + err.Error())
	}
	defer func() { ctx.Finalize(); ctx.Destroy() }()

	slots, err := ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		panic(fmt.Sprintf("verifySoftHSMToken: C_GetSlotList(true): %v (slots=%d)", err, len(slots)))
	}

	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			panic(fmt.Sprintf("verifySoftHSMToken: C_GetTokenInfo(slot %d): %v", slot, err))
		}
		if strings.TrimRight(info.Label, " ") != e2eTokenLabel {
			continue
		}
		if info.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
			panic(fmt.Sprintf("verifySoftHSMToken: CKF_TOKEN_INITIALIZED not set (flags=0x%x)", info.Flags))
		}
		if info.Flags&pkcs11.CKF_USER_PIN_INITIALIZED == 0 {
			panic(fmt.Sprintf("verifySoftHSMToken: CKF_USER_PIN_INITIALIZED not set (flags=0x%x)", info.Flags))
		}
		sh, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			panic("verifySoftHSMToken: OpenSession: " + err.Error())
		}
		if err := ctx.Login(sh, pkcs11.CKU_USER, []byte(os.Getenv("P11_PIN"))); err != nil {
			ctx.CloseSession(sh)
			panic("verifySoftHSMToken: Login(USER): " + err.Error())
		}
		ctx.Logout(sh)
		ctx.CloseSession(sh)
		fmt.Printf("verifySoftHSMToken: token %q on slot %d OK\n", e2eTokenLabel, slot)
		return
	}
	panic("verifySoftHSMToken: token " + e2eTokenLabel + " not found")
}

// initCrypto11 connects testCtx and testConfig to the ephemeral token.
func initCrypto11() {
	testConfig = &crypto11.Config{
		Path:       os.Getenv("P11_LIBRARY"),
		TokenLabel: os.Getenv("P11_TOKEN"),
		Pin:        os.Getenv("P11_PIN"),
	}
	var err error
	if testCtx, err = crypto11.Configure(testConfig); err != nil {
		panic("initCrypto11: " + err.Error())
	}
}

// shutdownCrypto11 closes the crypto11 session pool before the token directory
// is removed to prevent file-lock issues on Linux.
func shutdownCrypto11() {
	if testCtx != nil {
		_ = testCtx.Close()
	}
}
