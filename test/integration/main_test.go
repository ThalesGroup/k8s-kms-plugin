// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eclipse-keypont/crypto11/v2"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// testConfig and testCtx are the shared crypto11 handles for the integration
// suite. They are initialised by initCrypto11 (called from TestMain) once the
// ephemeral SoftHSM token is ready, and consumed by all *_integration_test.go.
var (
	testConfig *crypto11.Config
	testCtx    *crypto11.Context
)

// TestMain bootstraps an ephemeral SoftHSM token when PKCS11_MODULE is set,
// runs all tests against it, then cleans up.
//
// Without PKCS11_MODULE the suite exits immediately with no failures; individual
// tests guard themselves with skipIfNoLibrary so the output is clean.
//
// Both SoftHSMv2 (AES-GCM, AES-CBC, RSA-OAEP) and SoftHSMv3 (ML-KEM) are
// supported through the same initialisation path.
// Recommended module for ML-KEM: https://github.com/pqctoday-org/pqctoday-hsm
//
// Token initialisation is done entirely through the PKCS#11 API
// (C_InitToken / C_InitPIN) — no external tools (softhsm2-util) required.
//
// Example usage:
//
//	PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
//	PKCS11_PIN=1234 \
//	go test -v ./test/integration/
func TestMain(m *testing.M) {
	lib := os.Getenv("PKCS11_MODULE")
	if lib == "" {
		// No library configured — skip cleanly without panicking.
		os.Exit(m.Run())
	}

	teardown := initSoftHSMToken(lib)
	verifySoftHSMToken(lib)
	initCrypto11()

	code := m.Run()

	shutdownCrypto11()
	teardown()
	os.Exit(code)
}

const (
	integrationTokenLabel = "integration-test-token"
	integrationSoPin      = "0000"
	integrationDefaultPin = "1234"
)

// initSoftHSMToken creates a temp directory, writes a fresh softhsm2.conf
// (same INI format for SoftHSMv2 and SoftHSMv3), then initialises the token
// directly via the PKCS#11 API — no softhsm2-util required.
//
// PKCS#11 flow:
//  1. C_Initialize / C_GetSlotList(tokenPresent=false)  → find a free slot
//  2. C_InitToken                                        → set SO-PIN and label
//  3. C_GetSlotList(tokenPresent=true)                  → find the new slot
//  4. C_OpenSession / C_Login(SO) / C_InitPIN           → set user PIN
//
// Sets SOFTHSM2_CONF, PKCS11_TOKEN, and PKCS11_PIN environment variables so that
// crypto11 and all test helpers pick up the right token automatically.
// Returns a teardown function that removes the temp directory.
func initSoftHSMToken(modulePath string) func() {
	dir, err := os.MkdirTemp("", "softhsm-integration-*")
	if err != nil {
		panic("initSoftHSMToken: MkdirTemp: " + err.Error())
	}

	tokensDir := filepath.Join(dir, "tokens")
	if err := os.Mkdir(tokensDir, 0700); err != nil {
		panic("initSoftHSMToken: Mkdir(tokens): " + err.Error())
	}

	// softhsm2.conf format is identical for SoftHSMv2 and SoftHSMv3.
	conf := filepath.Join(dir, "softhsm2.conf")
	content := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n",
		tokensDir,
	)
	if err := os.WriteFile(conf, []byte(content), 0600); err != nil {
		panic("initSoftHSMToken: WriteFile(softhsm2.conf): " + err.Error())
	}

	// Must be set before the module is loaded so SoftHSM reads the right config.
	os.Setenv("SOFTHSM2_CONF", conf)

	if os.Getenv("PKCS11_PIN") == "" {
		os.Setenv("PKCS11_PIN", integrationDefaultPin)
	}
	userPin := os.Getenv("PKCS11_PIN")

	// ── Load module ───────────────────────────────────────────────────────────
	ctx, err := pkcs11.New(modulePath)
	if err != nil {
		panic("initSoftHSMToken: failed to load PKCS11_MODULE: " + modulePath + ": " + err.Error())
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		panic("initSoftHSMToken: C_Initialize: " + err.Error())
	}

	// ── Find an uninitialised slot ────────────────────────────────────────────
	slots, err := ctx.GetSlotList(false)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		panic(fmt.Sprintf("initSoftHSMToken: C_GetSlotList(false): %v (slots=%d)", err, len(slots)))
	}

	// ── Initialise the token (SO-PIN + label) ─────────────────────────────────
	if err := ctx.InitToken(slots[0], []byte(integrationSoPin), integrationTokenLabel); err != nil {
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: C_InitToken: " + err.Error())
	}

	// After C_InitToken the slot gets a new ID; re-fetch with tokenPresent=true.
	slots, err = ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		panic(fmt.Sprintf("initSoftHSMToken: C_GetSlotList(true) after InitToken: %v (slots=%d)", err, len(slots)))
	}

	// ── Set the user PIN via C_InitPIN ────────────────────────────────────────
	sh, err := ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: OpenSession: " + err.Error())
	}
	if err := ctx.Login(sh, pkcs11.CKU_SO, []byte(integrationSoPin)); err != nil {
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

	// Publish the token label so crypto11 and tests find the right token.
	os.Setenv("PKCS11_TOKEN", integrationTokenLabel)

	fmt.Printf("initSoftHSMToken: token %q initialised in %s\n", integrationTokenLabel, dir)

	return func() {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "initSoftHSMToken teardown: RemoveAll(%s): %v\n", dir, err)
		}
	}
}

// verifySoftHSMToken reopens the module and asserts that:
//   - exactly one initialised token is visible
//   - its label matches integrationTokenLabel
//   - CKF_TOKEN_INITIALIZED and CKF_USER_PIN_INITIALIZED are set
//   - a user login with PKCS11_PIN succeeds
//
// Panics with a descriptive message on failure so a mis-configured token
// causes an immediate, obvious failure rather than cryptic test errors later.
func verifySoftHSMToken(modulePath string) {
	ctx, err := pkcs11.New(modulePath)
	if err != nil {
		panic("verifySoftHSMToken: failed to load module " + modulePath + ": " + err.Error())
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		panic("verifySoftHSMToken: C_Initialize: " + err.Error())
	}
	defer func() {
		ctx.Finalize()
		ctx.Destroy()
	}()

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		panic("verifySoftHSMToken: C_GetSlotList: " + err.Error())
	}
	if len(slots) == 0 {
		panic("verifySoftHSMToken: no initialised token found — expected one with label " + integrationTokenLabel)
	}

	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			panic(fmt.Sprintf("verifySoftHSMToken: C_GetTokenInfo(slot %d): %v", slot, err))
		}

		label := strings.TrimRight(info.Label, " ")
		if label != integrationTokenLabel {
			continue
		}

		if info.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
			panic(fmt.Sprintf("verifySoftHSMToken: token %q: CKF_TOKEN_INITIALIZED not set (flags=0x%x)", integrationTokenLabel, info.Flags))
		}
		if info.Flags&pkcs11.CKF_USER_PIN_INITIALIZED == 0 {
			panic(fmt.Sprintf("verifySoftHSMToken: token %q: CKF_USER_PIN_INITIALIZED not set (flags=0x%x)", integrationTokenLabel, info.Flags))
		}

		// Smoke-test: open a user session.
		sh, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			panic(fmt.Sprintf("verifySoftHSMToken: OpenSession on token %q: %v", integrationTokenLabel, err))
		}
		if err := ctx.Login(sh, pkcs11.CKU_USER, []byte(os.Getenv("PKCS11_PIN"))); err != nil {
			ctx.CloseSession(sh)
			panic(fmt.Sprintf("verifySoftHSMToken: Login(USER) on token %q: %v", integrationTokenLabel, err))
		}
		ctx.Logout(sh)
		ctx.CloseSession(sh)

		fmt.Printf("verifySoftHSMToken: token %q on slot %d OK (flags=0x%x, lib=%s)\n",
			integrationTokenLabel, slot, info.Flags, modulePath)
		return
	}

	panic(fmt.Sprintf("verifySoftHSMToken: no token with label %q found among %d slot(s)", integrationTokenLabel, len(slots)))
}

// initCrypto11 connects the package-level testCtx and testConfig variables
// (used by all integration tests) to the ephemeral token that TestMain just
// created. Called once after verifySoftHSMToken.
func initCrypto11() {
	testConfig = &crypto11.Config{
		Path:       os.Getenv("PKCS11_MODULE"),
		TokenLabel: os.Getenv("PKCS11_TOKEN"),
		Pin:        os.Getenv("PKCS11_PIN"),
	}
	var err error
	if testCtx, err = crypto11.Configure(testConfig); err != nil {
		panic("initCrypto11: crypto11.Configure: " + err.Error())
	}
	fmt.Printf("initCrypto11: connected to token %q\n", testConfig.TokenLabel)
}

// shutdownCrypto11 closes the crypto11 session pool before the token directory
// is removed. Without this, SoftHSM may hold file locks that prevent cleanup.
func shutdownCrypto11() {
	if testCtx != nil {
		_ = testCtx.Close()
	}
}
