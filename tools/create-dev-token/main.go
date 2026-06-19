// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

// create-dev-token is a DEVELOPMENT / TESTING helper and is NOT part of the
// k8s-kms-plugin deployable. It MUST NOT be run against a production HSM, and
// the keys it creates (well-known PINs, fixed CKA_IDs) MUST NOT protect real
// data.
//
// It bootstraps a persistent SoftHSMv3 token with one key of
// every algorithm family supported by k8s-kms-plugin:
//
//	aes-gcm   — AES-256-GCM KEK
//	aes-cbc   — AES-256-CBC KEK  +  HMAC-SHA256 authentication key
//	rsa-oaep  — RSA-2048-OAEP key pair
//	ml-kem    — ML-KEM-768 key pair (skipped if the token does not support it)
//
// The resulting store can be inspected with p11tool / pkcs11-tool and used
// directly with k8s-kms-plugin serve.  It is intentionally NOT deleted on exit.
//
// Usage:
//
//	go run ./tools/create-dev-token \
//	  --lib   /path/to/libsofthsmv3.so \
//	  --dir   /tmp/k8s-kms-plugin-devtoken   # default
//	  --pin   1234                            # default
//
// To automatically export SOFTHSM2_CONF into the current shell session:
//
//	eval "$(create-dev-token --lib /path/to/libsofthsmv3.so)"
//	# or
//	source <(create-dev-token --lib /path/to/libsofthsmv3.so)
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ThalesGroup/crypto11"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// version is set at build time via -ldflags "-X main.version=<git-describe>".
var version = "dev"

// ANSI color codes; zeroed when NO_COLOR is set (https://no-color.org).
var (
	cReset  string
	cBold   string
	cDim    string
	cRed    string
	cGreen  string
	cYellow string
	cCyan   string
)

func init() {
	if os.Getenv("NO_COLOR") == "" {
		cReset  = "\033[0m"
		cBold   = "\033[1m"
		cDim    = "\033[2m"
		cRed    = "\033[31m"
		cGreen  = "\033[32m"
		cYellow = "\033[33m"
		cCyan   = "\033[36m"
	}
}

const (
	tokenLabel = "k8s-kms-plugin-dev"
	soPin      = "0000"
)

// Fixed short CKA_IDs — stable across runs, easy to reference in p11tool URIs.
var (
	idAESGCM = []byte{0x01}
	idAESCBC = []byte{0x02}
	idHMAC   = []byte{0x03}
	idRSA    = []byte{0x04}
	idMLKEM  = []byte{0x05}

	labelAESGCM = []byte("dev-aes-gcm-kek")
	labelAESCBC = []byte("dev-aes-cbc-kek")
	labelHMAC   = []byte("dev-hmac-sha256")
	labelRSA    = []byte("dev-rsa-2048-oaep")
	labelMLKEM  = []byte("dev-ml-kem-768")
)

// warnTestingOnly prints a prominent banner making it unmistakable that this
// tool is a development/testing helper and must never touch a production HSM.
func warnTestingOnly() {
	const banner = `╔════════════════════════════════════════════════════════════════════════╗
║  create-dev-token — DEVELOPMENT / TESTING helper                       ║
║                                                                        ║
║  Provisions a throwaway SoftHSMv3 token with WELL-KNOWN PINs and FIXED ║
║  key IDs for manually exercising k8s-kms-plugin.                       ║
║                                                                        ║
║  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️                                                      ║
║  DO NOT run this against a production HSM, and DO NOT use the keys it  ║
║  creates to protect real data. For local testing only.                 ║
╚════════════════════════════════════════════════════════════════════════╝
`
	fmt.Fprint(os.Stderr, cBold+cYellow+banner+cReset)
}

func main() {
	warnTestingOnly()

	fatalf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, cBold+cRed+"error: "+cReset+format+"\n", a...)
		os.Exit(1)
	}

	lib          := flag.String("lib", os.Getenv("PKCS11_MODULE"), "path to the SoftHSMv3 shared library (or set PKCS11_MODULE)")
	dir          := flag.String("dir", "/tmp/k8s-kms-plugin-devtoken", "directory to create the token store in")
	pin          := flag.String("pin", "1234", "user PIN to set on the token")
	ver          := flag.Bool("version", false, "print version and exit")
	noEnvExport  := flag.Bool("no-env-export", false, "do not print 'export SOFTHSM2_CONF=...' to stdout")
	flag.Parse()

	if *ver {
		fmt.Printf("create-dev-token %s\n", version)
		os.Exit(0)
	}

	if *lib == "" {
		fatalf("--lib is required (or set PKCS11_MODULE)")
	}

	// ── Create SoftHSM directory ─────────────────────────────────────────────

	if _, err := os.Stat(*dir); err == nil {
		fatalf("directory %s already exists — remove it first for a fresh token", *dir)
	}
	tokensDir := filepath.Join(*dir, "tokens")
	if err := os.MkdirAll(tokensDir, 0700); err != nil {
		fatalf("MkdirAll %s: %v", tokensDir, err)
	}

	confPath := filepath.Join(*dir, "softhsm2.conf")
	confContent := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n",
		tokensDir,
	)
	if err := os.WriteFile(confPath, []byte(confContent), 0600); err != nil {
		fatalf("WriteFile %s: %v", confPath, err)
	}
	os.Setenv("SOFTHSM2_CONF", confPath)
	fmt.Fprintf(os.Stderr, "%s✔%s SoftHSM store created: %s\n", cBold+cGreen, cReset, *dir)

	// ── Initialise token (C_InitToken + C_InitPIN) ────────────────────────────

	p11, err := pkcs11.New(*lib)
	if err != nil {
		fatalf("failed to load library: %s: %v", *lib, err)
	}
	if err := p11.Initialize(); err != nil {
		p11.Destroy()
		fatalf("C_Initialize: %v", err)
	}

	slots, err := p11.GetSlotList(false)
	if err != nil || len(slots) == 0 {
		p11.Finalize()
		p11.Destroy()
		fatalf("C_GetSlotList: %v (slots=%d)", err, len(slots))
	}
	if err := p11.InitToken(slots[0], []byte(soPin), tokenLabel); err != nil {
		p11.Finalize()
		p11.Destroy()
		fatalf("C_InitToken: %v", err)
	}

	// After InitToken the token moves to a new slot — re-enumerate.
	slots, err = p11.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		p11.Finalize()
		p11.Destroy()
		fatalf("C_GetSlotList(true): %v (slots=%d)", err, len(slots))
	}
	sh, err := p11.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		p11.Finalize()
		p11.Destroy()
		fatalf("OpenSession: %v", err)
	}
	if err := p11.Login(sh, pkcs11.CKU_SO, []byte(soPin)); err != nil {
		p11.CloseSession(sh)
		p11.Finalize()
		p11.Destroy()
		fatalf("Login(SO): %v", err)
	}
	if err := p11.InitPIN(sh, []byte(*pin)); err != nil {
		p11.Logout(sh)
		p11.CloseSession(sh)
		p11.Finalize()
		p11.Destroy()
		fatalf("C_InitPIN: %v", err)
	}
	p11.Logout(sh)
	p11.CloseSession(sh)
	p11.Finalize()
	p11.Destroy()
	fmt.Fprintf(os.Stderr, "%s✔%s Token initialised   label=%s  SO-PIN=%s  user-PIN=%s\n", cBold+cGreen, cReset, tokenLabel, soPin, *pin)

	// ── Connect via crypto11 ──────────────────────────────────────────────────

	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       *lib,
		TokenLabel: tokenLabel,
		Pin:        *pin,
	})
	if err != nil {
		fatalf("crypto11.Configure: %v", err)
	}
	defer ctx.Close()

	// ── AES-256-GCM KEK ───────────────────────────────────────────────────────

	gcmKey, err := ctx.GenerateSecretKeyWithLabel(idAESGCM, labelAESGCM, 256, crypto11.CipherAES)
	if err != nil {
		fatalf("GenerateSecretKeyWithLabel AES-256-GCM: %v", err)
	}
	_ = gcmKey
	fmt.Fprintf(os.Stderr, "%s✔%s AES-256-GCM KEK     key label=%s  id=0x%02x\n", cBold+cGreen, cReset, labelAESGCM, idAESGCM)

	// ── AES-256-CBC KEK ───────────────────────────────────────────────────────

	cbcKey, err := ctx.GenerateSecretKeyWithLabel(idAESCBC, labelAESCBC, 256, crypto11.CipherAES)
	if err != nil {
		fatalf("GenerateSecretKeyWithLabel AES-256-CBC: %v", err)
	}
	_ = cbcKey
	fmt.Fprintf(os.Stderr, "%s✔%s AES-256-CBC KEK     key label=%s  id=0x%02x\n", cBold+cGreen, cReset, labelAESCBC, idAESCBC)

	// ── HMAC-SHA256 key (CKK_GENERIC_SECRET, CKA_SIGN=true) ──────────────────

	hmacAttrs, err := crypto11.NewAttributeSetWithIDAndLabel(idHMAC, labelHMAC)
	if err != nil {
		fatalf("NewAttributeSetWithIDAndLabel HMAC: %v", err)
	}
	if err := hmacAttrs.Set(crypto11.CkaSign, true); err != nil {
		fatalf("hmacAttrs.Set(CkaSign): %v", err)
	}
	if err := hmacAttrs.Set(crypto11.CkaVerify, true); err != nil {
		fatalf("hmacAttrs.Set(CkaVerify): %v", err)
	}
	hmacKey, err := ctx.GenerateSecretKeyWithAttributes(hmacAttrs, 256, crypto11.CipherGeneric)
	if err != nil {
		fatalf("GenerateSecretKeyWithAttributes HMAC-SHA256: %v", err)
	}
	_ = hmacKey
	fmt.Fprintf(os.Stderr, "%s✔%s HMAC-SHA256         key label=%s  id=0x%02x\n", cBold+cGreen, cReset, labelHMAC, idHMAC)

	// ── RSA-2048 key pair ──────────────────────────────────────────────────────

	rsaKP, err := ctx.GenerateRSAKeyPairWithLabel(idRSA, labelRSA, 2048)
	if err != nil {
		fatalf("GenerateRSAKeyPairWithLabel RSA-2048: %v", err)
	}
	_ = rsaKP
	fmt.Fprintf(os.Stderr, "%s✔%s RSA-2048-OAEP       key label=%s  id=0x%02x\n", cBold+cGreen, cReset, labelRSA, idRSA)

	// ── ML-KEM-768 key pair (skipped gracefully if unsupported) ──────────────

	mlkemKP, err := ctx.GenerateMLKEMKeyPairWithLabel(idMLKEM, labelMLKEM, crypto11.MLKEM768)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s⚠%s ML-KEM-768 skipped  (token does not support CKM_ML_KEM_KEY_PAIR_GEN: %v)\n", cBold+cYellow, cReset, err)
		fmt.Fprintf(os.Stderr, "  Requires SoftHSMv3 from https://github.com/pqctoday-org/pqctoday-hsm\n")
	} else {
		_ = mlkemKP
		fmt.Fprintf(os.Stderr, "%s✔%s ML-KEM-768          key label=%s  id=0x%02x\n", cBold+cGreen, cReset, labelMLKEM, idMLKEM)
	}

	// ── Print usage instructions ───────────────────────────────────────────────

	hr := cDim + strings.Repeat("─", 76) + cReset
	// section returns a dim header line padded to 76 visible columns.
	// All titles are ASCII so len() == display width.
	section := func(title string) string {
		return cDim + "── " + title + " " + strings.Repeat("─", 72-len(title)) + cReset
	}
	v := func(s string) string { return cCyan + s + cReset }

	fmt.Fprintf(os.Stderr, `
%s
Token store   : %s
Token label   : %s
User PIN      : %s
SOFTHSM2_CONF : %s
%s

%s

  GNUTLS_SO_PIN="%s" GNUTLS_PIN="%s" p11tool \
    --provider "%s" \
    --login \
    --list-all "pkcs11:token=%s"

%s

  pkcs11-tool \
    --module "%s" \
    --login --pin "%s" \
    --token-label "%s" \
    --list-objects

%s

  k8s-kms-plugin serve \
    --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
    --p11-lib   "%s" \
    --p11-label "%s" \
    --p11-pin   "%s" \
    --p11-key-label %s \
    --algorithm-family aes-gcm

%s

  k8s-kms-plugin serve \
    --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
    --p11-lib        "%s" \
    --p11-label      "%s" \
    --p11-pin        "%s" \
    --p11-key-label   %s \
    --p11-hmac-label  %s \
    --algorithm-family aes-cbc

%s

  k8s-kms-plugin serve \
    --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
    --p11-lib   "%s" \
    --p11-label "%s" \
    --p11-pin   "%s" \
    --p11-key-label %s \
    --algorithm-family rsa-oaep

%s

  k8s-kms-plugin serve \
    --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
    --p11-lib   "%s" \
    --p11-label "%s" \
    --p11-pin   "%s" \
    --p11-key-label %s \
    --algorithm-family ml-kem

%s

  cd scripts/grpcurl
  ./grpcurl-roundtrip-test.sh "hello dev token" \
    /run/user/$(id -u)/k8s-kms-plugin-dev.sock

%s
`,
		hr,
		v(*dir), v(tokenLabel), v(*pin), v(confPath),
		hr,
		// p11tool
		section("List all objects with p11tool"),
		soPin, *pin, *lib, tokenLabel,
		// pkcs11-tool
		section("List all objects with pkcs11-tool"),
		*lib, *pin, tokenLabel,
		// aes-gcm
		section("k8s-kms-plugin: AES-GCM"),
		*lib, tokenLabel, *pin, labelAESGCM,
		// aes-cbc
		section("k8s-kms-plugin: AES-CBC + HMAC"),
		*lib, tokenLabel, *pin, labelAESCBC, labelHMAC,
		// rsa-oaep
		section("k8s-kms-plugin: RSA-OAEP"),
		*lib, tokenLabel, *pin, labelRSA,
		// ml-kem
		section("k8s-kms-plugin: ML-KEM"),
		*lib, tokenLabel, *pin, labelMLKEM,
		// grpcurl
		section("grpcurl round-trip test"),
		hr,
	)

	// ── Export SOFTHSM2_CONF to stdout for eval / source ──────────────────────
	//
	// All informational output above goes to stderr so that eval captures only
	// this export statement:
	//
	//   eval "$(create-dev-token --lib ... --dir ... --pin ...)"
	//   source <(create-dev-token --lib ... --dir ... --pin ...)

	if !*noEnvExport {
		fmt.Fprintf(os.Stderr, "%s⚡%s SOFTHSM2_CONF exported to stdout — apply in current shell:\n", cBold+cCyan, cReset)
		fmt.Fprintf(os.Stderr, "   eval \"$(create-dev-token --lib \"%s\" --dir \"%s\" --pin \"%s\")\"\n", *lib, *dir, *pin)
		fmt.Fprintf(os.Stderr, "   Pass --no-env-export to suppress.\n\n")
		fmt.Printf("export SOFTHSM2_CONF=%q\n", confPath)
	}
}
