// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

// Package e2e exercises the k8s-kms-plugin binary end-to-end against an
// ephemeral SoftHSMv3 token, using grpcurl to drive the KMS v2 gRPC API.
//
// Required environment variables:
//
//	PKCS11_MODULE   path to the PKCS#11 shared library
//	PKCS11_PIN       user PIN (default: 1234)
//
// The k8s-kms-plugin binary must be built before running these tests:
//
//	make build
//	PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so go test -v ./test/e2e/
//
// `make build` places the binary in dist/k8s-kms-plugin.
//
// grpcurl must also be on PATH — it is the gRPC client these tests drive the
// plugin with:
//
//	go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
//
// The KMS v2 api.proto grpcurl needs is resolved automatically, at the k8s.io/kms
// version go.mod selects — from the module cache when it is populated, otherwise
// downloaded. See resolveAPIProto.
//
// aes-gcm, aes-cbc and rsa-oaep work with SoftHSMv2 or SoftHSMv3.
// ml-kem requires SoftHSMv3: https://github.com/pqctoday-org/pqctoday-hsm
package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-keypont/crypto11/v2"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// Package-level state initialised by TestMain and consumed by all tests.
var (
	testConfig *crypto11.Config
	testCtx    *crypto11.Context
	pluginBin  string // absolute path to the k8s-kms-plugin binary
	repoRoot   string // absolute path to the repository root
	protoFile  string // KMS v2 api.proto matching the k8s.io/kms version in go.mod
)

const (
	e2eTokenLabel = "e2e-test-token"
	e2eSoPin      = "0000"
	e2eDefaultPin = "1234"
)

// TestMain bootstraps an ephemeral SoftHSM token, verifies it, connects
// crypto11, locates the plugin binary and grpcurl, then runs all tests.
// Without PKCS11_MODULE the whole suite is skipped cleanly.
func TestMain(m *testing.M) {
	lib := os.Getenv("PKCS11_MODULE")
	if lib == "" {
		fmt.Fprintln(os.Stderr, "PKCS11_MODULE not set — skipping e2e tests")
		os.Exit(0)
	}

	var err error
	// Working directory for test binaries is the package directory (test/e2e/).
	repoRoot, err = filepath.Abs("../..")
	if err != nil {
		panic("TestMain: filepath.Abs: " + err.Error())
	}
	protoFile = resolveAPIProto()

	pluginBin = findPluginBin(repoRoot)
	// Before the token setup below, which is far more expensive than this check
	// and pointless without a working gRPC client.
	requireGrpcurl()

	teardown := initSoftHSMToken(lib)
	verifySoftHSMToken(lib)
	initCrypto11()

	code := m.Run()

	shutdownCrypto11()
	teardown()
	os.Exit(code)
}

// kmsModule is the module owning the KMS v2 service definition these tests drive.
const kmsModule = "k8s.io/kms"

// apiProtoPathInModule is api.proto's location inside that module.
var apiProtoPathInModule = filepath.Join("apis", "v2", "api.proto")

// resolveAPIProto returns the path to the KMS v2 api.proto that matches the k8s.io/kms version
// this repository builds against, or fails the suite explaining why it could not.
//
// The version is never hardcoded. grpcurl uses this file as the service definition, so a proto
// from a different release than the plugin implements would have the tests exercising a contract
// the binary does not serve — silently, for any field that happens to still line up. The helper
// scripts under scripts/grpcurl/ show how that goes wrong: they pin v0.34.1 while go.mod is on
// v0.36.3.
//
// Resolution order:
//
//  1. The module cache, located with `go list -m`. This is authoritative — it is the very copy
//     the plugin compiles against — needs no network, and cannot drift.
//  2. An HTTPS fetch from the kubernetes/kms tag matching the resolved version, used when the
//     module cache is unavailable (a vendored or trimmed checkout, for instance).
//
// Neither path writes into the repository: the cached file is read in place, and a download goes
// to a temp file. Nothing here touches the git-ignored scripts/grpcurl/api.proto, which the
// shell helpers manage on their own.
func resolveAPIProto() string {
	version, dir, err := kmsModuleInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: cannot resolve the %s module: %v\n", kmsModule, err)
		fmt.Fprintln(os.Stderr, "  run 'go mod download' and retry")
		os.Exit(1)
	}

	if dir != "" {
		cached := filepath.Join(dir, apiProtoPathInModule)
		if _, statErr := os.Stat(cached); statErr == nil {
			fmt.Printf("resolveAPIProto: using %s %s api.proto from the module cache\n", kmsModule, version)
			return cached
		}
	}

	fetched, err := fetchAPIProto(version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: could not obtain api.proto for %s %s: %v\n", kmsModule, version, err)
		fmt.Fprintln(os.Stderr, "  the module cache has no copy and the download failed;")
		fmt.Fprintln(os.Stderr, "  run 'go mod download "+kmsModule+"' or restore network access")
		os.Exit(1)
	}
	fmt.Printf("resolveAPIProto: downloaded %s %s api.proto to %s\n", kmsModule, version, fetched)
	return fetched
}

// kmsModuleInfo asks the go tool for the selected version of the KMS module and its directory in
// the module cache. Dir is empty when the module is known but not extracted, which is not an
// error here: the caller falls back to downloading the proto.
func kmsModuleInfo() (version, dir string, err error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}}\t{{.Dir}}", kmsModule)
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", "", fmt.Errorf("go list -m %s: %w: %s", kmsModule, err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", "", fmt.Errorf("go list -m %s: %w", kmsModule, err)
	}

	version, dir, _ = strings.Cut(strings.TrimSpace(string(out)), "\t")
	if version == "" {
		return "", "", fmt.Errorf("go list -m %s returned no version", kmsModule)
	}
	return version, dir, nil
}

// fetchAPIProto downloads api.proto for the given module version into a temp file.
//
// The URL is built from the resolved version so the download can never disagree with the module
// the plugin was compiled against. A non-200 response is reported with its status, because the
// usual cause is a version whose tag does not exist upstream.
func fetchAPIProto(version string) (string, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/kubernetes/kms/refs/tags/%s/%s",
		version, filepath.ToSlash(apiProtoPathInModule))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("building request for %s: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "fetchAPIProto: closing response body: %v\n", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching %s: unexpected status %s", url, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", url, err)
	}
	// A truncated or error page would surface as a confusing grpcurl parse failure much later.
	if !bytes.Contains(body, []byte("service KeyManagementService")) {
		return "", fmt.Errorf("%s does not look like the KMS v2 api.proto (%d bytes)", url, len(body))
	}

	dir, err := os.MkdirTemp("", "k8s-kms-plugin-e2e-proto-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir for api.proto: %w", err)
	}
	path := filepath.Join(dir, "api.proto")
	if err := os.WriteFile(path, body, 0600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// findPluginBin looks for the k8s-kms-plugin binary in dist/ (where `make
// build` places it), then at the repo root (legacy location), then in PATH.
func findPluginBin(root string) string {
	candidates := []string{
		filepath.Join(root, "dist", "k8s-kms-plugin"),
		filepath.Join(root, "k8s-kms-plugin"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, "k8s-kms-plugin")
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	panic("k8s-kms-plugin binary not found in dist/, repo root, or PATH — run 'make build' first")
}

// requireGrpcurl verifies that grpcurl is actually runnable, so a missing client
// is reported once here rather than as an identical failure in every sub-test —
// after the token, the keys and the plugin process have all been set up for
// nothing.
//
// Probes by running grpcurl rather than with exec.LookPath, which is as
// shim-blind as `command -v`: a goenv/asdf shim stays on PATH even when the tool
// is not installed for the active Go version, so LookPath resolves it happily and
// the shim only fails once called, with "goenv: 'grpcurl' command not found".
// Exit 127 — missing binary, or a shim with nothing behind it — is the only
// status treated as missing, so a grpcurl build that rejects --version still
// passes. Mirrors the `define require` rule in the Makefile and the preflight in
// scripts/grpcurl/.
func requireGrpcurl() {
	out, err := exec.Command("grpcurl", "--version").CombinedOutput()
	if err == nil {
		return
	}

	var exitErr *exec.ExitError
	missing := errors.Is(err, exec.ErrNotFound) ||
		(errors.As(err, &exitErr) && exitErr.ExitCode() == 127)
	if !missing {
		return // it ran and failed on its own terms; that is not our problem here
	}

	// Exits rather than panicking: a missing tool is a prerequisite the caller has
	// to install, not a broken invariant, and the goroutine dump a panic prints
	// here would only restate this call path while burying the install command.
	// Same idiom as the PKCS11_MODULE check in TestMain. Nothing is deferred and
	// no token exists yet at this point, so there is nothing for os.Exit to skip.
	fmt.Fprintf(os.Stderr, "grpcurl is required by these tests but is not runnable: %v\n", err)
	if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
		fmt.Fprintf(os.Stderr, "  grpcurl output: %s\n", trimmed)
	}
	fmt.Fprintln(os.Stderr,
		"  install it with: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest")
	os.Exit(1)
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

	if os.Getenv("PKCS11_PIN") == "" {
		os.Setenv("PKCS11_PIN", e2eDefaultPin)
	}
	userPin := os.Getenv("PKCS11_PIN")

	ctx, err := pkcs11.New(modulePath)
	if err != nil {
		panic("initSoftHSMToken: failed to load PKCS11_MODULE: " + modulePath + ": " + err.Error())
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

	os.Setenv("PKCS11_TOKEN", e2eTokenLabel)
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
		if err := ctx.Login(sh, pkcs11.CKU_USER, []byte(os.Getenv("PKCS11_PIN"))); err != nil {
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
		Path:       os.Getenv("PKCS11_MODULE"),
		TokenLabel: os.Getenv("PKCS11_TOKEN"),
		Pin:        os.Getenv("PKCS11_PIN"),
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
