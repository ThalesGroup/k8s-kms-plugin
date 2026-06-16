/*
 * Copyright 2026 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

// create-dev-token bootstraps a persistent SoftHSMv3 token with one key of
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

func main() {
	lib := flag.String("lib", os.Getenv("P11_LIBRARY"), "path to the SoftHSMv3 shared library (or set P11_LIBRARY)")
	dir := flag.String("dir", "/tmp/k8s-kms-plugin-devtoken", "directory to create the token store in")
	pin := flag.String("pin", "1234", "user PIN to set on the token")
	flag.Parse()

	if *lib == "" {
		fmt.Fprintln(os.Stderr, "error: --lib is required (or set P11_LIBRARY)")
		os.Exit(1)
	}

	fatalf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
		os.Exit(1)
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
	fmt.Printf("✔ SoftHSM store created: %s\n", *dir)

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
		p11.Finalize(); p11.Destroy()
		fatalf("C_GetSlotList: %v (slots=%d)", err, len(slots))
	}
	if err := p11.InitToken(slots[0], []byte(soPin), tokenLabel); err != nil {
		p11.Finalize(); p11.Destroy()
		fatalf("C_InitToken: %v", err)
	}

	// After InitToken the token moves to a new slot — re-enumerate.
	slots, err = p11.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		p11.Finalize(); p11.Destroy()
		fatalf("C_GetSlotList(true): %v (slots=%d)", err, len(slots))
	}
	sh, err := p11.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		p11.Finalize(); p11.Destroy()
		fatalf("OpenSession: %v", err)
	}
	if err := p11.Login(sh, pkcs11.CKU_SO, []byte(soPin)); err != nil {
		p11.CloseSession(sh); p11.Finalize(); p11.Destroy()
		fatalf("Login(SO): %v", err)
	}
	if err := p11.InitPIN(sh, []byte(*pin)); err != nil {
		p11.Logout(sh); p11.CloseSession(sh); p11.Finalize(); p11.Destroy()
		fatalf("C_InitPIN: %v", err)
	}
	p11.Logout(sh)
	p11.CloseSession(sh)
	p11.Finalize()
	p11.Destroy()
	fmt.Printf("✔ Token initialised   label=%s  SO-PIN=%s  user-PIN=%s\n", tokenLabel, soPin, *pin)

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
	fmt.Printf("✔ AES-256-GCM KEK     key label=%s  id=0x%02x\n", labelAESGCM, idAESGCM)

	// ── AES-256-CBC KEK ───────────────────────────────────────────────────────

	cbcKey, err := ctx.GenerateSecretKeyWithLabel(idAESCBC, labelAESCBC, 256, crypto11.CipherAES)
	if err != nil {
		fatalf("GenerateSecretKeyWithLabel AES-256-CBC: %v", err)
	}
	_ = cbcKey
	fmt.Printf("✔ AES-256-CBC KEK     key label=%s  id=0x%02x\n", labelAESCBC, idAESCBC)

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
	fmt.Printf("✔ HMAC-SHA256         key label=%s  id=0x%02x\n", labelHMAC, idHMAC)

	// ── RSA-2048 key pair ──────────────────────────────────────────────────────

	rsaKP, err := ctx.GenerateRSAKeyPairWithLabel(idRSA, labelRSA, 2048)
	if err != nil {
		fatalf("GenerateRSAKeyPairWithLabel RSA-2048: %v", err)
	}
	_ = rsaKP
	fmt.Printf("✔ RSA-2048-OAEP       key label=%s  id=0x%02x\n", labelRSA, idRSA)

	// ── ML-KEM-768 key pair (skipped gracefully if unsupported) ──────────────

	mlkemKP, err := ctx.GenerateMLKEMKeyPairWithLabel(idMLKEM, labelMLKEM, crypto11.MLKEM768)
	if err != nil {
		fmt.Printf("⚠ ML-KEM-768 skipped  (token does not support CKM_ML_KEM_KEY_PAIR_GEN: %v)\n", err)
		fmt.Printf("  Requires SoftHSMv3 from https://github.com/pqctoday-org/pqctoday-hsm\n")
	} else {
		_ = mlkemKP
		fmt.Printf("✔ ML-KEM-768          key label=%s  id=0x%02x\n", labelMLKEM, idMLKEM)
	}

	// ── Print usage instructions ───────────────────────────────────────────────

	hr := strings.Repeat("─", 76)
	fmt.Printf(`
%s
Token store : %s
Token label : %s
User PIN    : %s
SOFTHSM2_CONF=%s
%s

Set this in every terminal session before using the token:

  export SOFTHSM2_CONF="%s"

── List all objects with p11tool ─────────────────────────────────────────────

  GNUTLS_SO_PIN="%s" GNUTLS_PIN="%s" p11tool \
    --provider "%s" \
    --login \
    --list-all "pkcs11:token=%s"

── List all objects with pkcs11-tool ────────────────────────────────────────

  pkcs11-tool \
    --module "%s" \
    --login --pin "%s" \
    --token-label "%s" \
    --list-objects

── k8s-kms-plugin: AES-GCM ──────────────────────────────────────────────────

  k8s-kms-plugin serve \
    --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
    --p11-lib   "%s" \
    --p11-label "%s" \
    --p11-pin   "%s" \
    --p11-key-label %s \
    --algorithm-family aes-gcm

── k8s-kms-plugin: AES-CBC + HMAC ──────────────────────────────────────────

  k8s-kms-plugin serve \
    --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
    --p11-lib        "%s" \
    --p11-label      "%s" \
    --p11-pin        "%s" \
    --p11-key-label   %s \
    --p11-hmac-label  %s \
    --algorithm-family aes-cbc

── k8s-kms-plugin: RSA-OAEP ─────────────────────────────────────────────────

  k8s-kms-plugin serve \
    --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
    --p11-lib   "%s" \
    --p11-label "%s" \
    --p11-pin   "%s" \
    --p11-key-label %s \
    --algorithm-family rsa-oaep

── k8s-kms-plugin: ML-KEM ───────────────────────────────────────────────────

  k8s-kms-plugin serve \
    --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
    --p11-lib   "%s" \
    --p11-label "%s" \
    --p11-pin   "%s" \
    --p11-key-label %s \
    --algorithm-family ml-kem

── grpcurl round-trip test ──────────────────────────────────────────────────

  cd scripts/grpcurl
  ./grpcurl-roundtrip-test.sh "hello dev token" \
    /run/user/$(id -u)/k8s-kms-plugin-dev.sock

%s
`,
		hr, *dir, tokenLabel, *pin, confPath, hr,
		// export
		confPath,
		// p11tool
		soPin, *pin, *lib, tokenLabel,
		// pkcs11-tool
		*lib, *pin, tokenLabel,
		// aes-gcm serve
		*lib, tokenLabel, *pin, labelAESGCM,
		// aes-cbc serve
		*lib, tokenLabel, *pin, labelAESCBC, labelHMAC,
		// rsa-oaep serve
		*lib, tokenLabel, *pin, labelRSA,
		// ml-kem serve
		*lib, tokenLabel, *pin, labelMLKEM,
		hr,
	)
}
