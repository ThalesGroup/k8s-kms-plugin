// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package providers

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
	"testing"

	k8skmsv2 "k8s.io/kms/apis/v2"
)

// FuzzGetIVFromDecryptRequest drives the JWE compact parser with arbitrary bytes.
//
// DecryptRequest.Ciphertext is the least trusted input the plugin handles: it arrives
// over gRPC from the apiserver and is parsed before any key material authenticates it.
// The target asserts the parser's contract rather than a specific output — it must
// either fail or return a non-empty IV, and it must never panic.
func FuzzGetIVFromDecryptRequest(f *testing.F) {
	for _, jwe := range validJWEs {
		f.Add([]byte(jwe))
	}
	for _, jwe := range invalidJWEs {
		f.Add([]byte(jwe))
	}

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		iv, err := getIVFromDecryptRequest(&k8skmsv2.DecryptRequest{Ciphertext: ciphertext})
		if err != nil {
			if iv != nil {
				t.Fatalf("getIVFromDecryptRequest returned both an IV (%d bytes) and an error: %v", len(iv), err)
			}
			return
		}
		if len(iv) == 0 {
			t.Fatal("getIVFromDecryptRequest returned a nil error with an empty IV")
		}
	})
}

// FuzzValidateHexKeyID checks that the CKA_ID validator's guarantees actually hold for
// every input, so callers such as decryptWithContext can rely on them before handing the
// value to hex.DecodeString and the HSM.
func FuzzValidateHexKeyID(f *testing.F) {
	f.Add("")
	f.Add("dca8591")
	f.Add("dca85912cc5e712d")
	f.Add(strings.Repeat("a", maxCkaIDHexLen))
	f.Add(strings.Repeat("a", maxCkaIDHexLen+2))
	f.Add("zz")

	f.Fuzz(func(t *testing.T, hexKeyID string) {
		if err := validateHexKeyID(hexKeyID); err != nil {
			return
		}
		switch {
		case len(hexKeyID) == 0:
			t.Fatal("validateHexKeyID accepted an empty key ID")
		case len(hexKeyID)%2 != 0:
			t.Fatalf("validateHexKeyID accepted an odd-length key ID (%d chars)", len(hexKeyID))
		case len(hexKeyID) > maxCkaIDHexLen:
			t.Fatalf("validateHexKeyID accepted %d chars, over the PKCS#11 maximum of %d", len(hexKeyID), maxCkaIDHexLen)
		}
		// Accepted IDs are only length-checked, so a decode failure here is expected;
		// what must hold is that the decoded ID stays inside the PKCS#11 attribute bound.
		if decoded, err := hex.DecodeString(hexKeyID); err == nil && len(decoded) > maxCkaIDHexLen/2 {
			t.Fatalf("validated key ID decodes to %d bytes, over the PKCS#11 maximum of %d", len(decoded), maxCkaIDHexLen/2)
		}
	})
}

// FuzzKeyIDBoundsAreConsistent ties the plugin's own CKA_ID bound to the platform's.
//
// The KeyId this plugin reports is the hex encoding of a CKA_ID, and the Kubernetes API server
// rejects any KeyId over maxKMSv2KeyIDSize. So every hex CKA_ID that validateHexKeyID accepts
// must also satisfy validateKMSv2KeyID — otherwise the plugin can accept a --p11-key-id at
// startup that makes every later Status response invalid.
//
// A compile-time assertion in p11.go already pins the two constants together; this target
// covers the validators actually agreeing, which the constants alone do not guarantee.
func FuzzKeyIDBoundsAreConsistent(f *testing.F) {
	f.Add("dca85912cc5e712d")
	f.Add(strings.Repeat("ab", maxCkaIDHexLen/2))
	f.Add("")

	f.Fuzz(func(t *testing.T, hexKeyID string) {
		if err := validateHexKeyID(hexKeyID); err != nil {
			return // already rejected upstream; the KMS bound is not reached
		}
		if err := validateKMSv2KeyID(hexKeyID); err != nil {
			t.Fatalf("validateHexKeyID accepted a %d-char CKA_ID that KMS v2 rejects: %v", len(hexKeyID), err)
		}
	})
}

// FuzzValidateKMSv2KeyID checks the KMS v2 bound in isolation, including the CKA_IDs that
// reach it from the HSM rather than from the operator — the ones validateHexKeyID never sees.
func FuzzValidateKMSv2KeyID(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0xDE, 0xAD})
	f.Add(bytes.Repeat([]byte{0xAB}, maxKMSv2KeyIDSize/2))   // exactly at the limit once hex-encoded
	f.Add(bytes.Repeat([]byte{0xAB}, maxKMSv2KeyIDSize/2+1)) // one byte over

	f.Fuzz(func(t *testing.T, ckaID []byte) {
		hexKeyID := hex.EncodeToString(ckaID)
		err := validateKMSv2KeyID(hexKeyID)

		// Mirror of the API server's ValidateKeyID: empty or over the cap is rejected, and
		// everything else is accepted.
		wantRejected := len(hexKeyID) == 0 || len(hexKeyID) > maxKMSv2KeyIDSize
		if wantRejected && err == nil {
			t.Fatalf("validateKMSv2KeyID accepted a %d-char KeyId the API server would reject", len(hexKeyID))
		}
		if !wantRejected && err != nil {
			t.Fatalf("validateKMSv2KeyID rejected a %d-char KeyId the API server would accept: %v", len(hexKeyID), err)
		}
	})
}

// FuzzValidateCkaLabel checks the CKA_LABEL validator's bound, which protects the HSM
// from over-long attribute values.
func FuzzValidateCkaLabel(f *testing.F) {
	f.Add("")
	f.Add("k8s-kms-plugin-kek")
	f.Add(strings.Repeat("l", maxCkaLabelSize))
	f.Add(strings.Repeat("l", maxCkaLabelSize+1))
	f.Add("étiquette-non-ascii")

	f.Fuzz(func(t *testing.T, label string) {
		if err := validateCkaLabel(label); err != nil {
			return
		}
		if len(label) == 0 {
			t.Fatal("validateCkaLabel accepted an empty label")
		}
		if len(label) > maxCkaLabelSize {
			t.Fatalf("validateCkaLabel accepted %d bytes, over the PKCS#11 maximum of %d", len(label), maxCkaLabelSize)
		}
	})
}

// FuzzMlkemAAD checks that the ML-KEM additional authenticated data encoding is
// injective: two different KEM ciphertexts must never produce the same AAD. Injectivity
// is what makes the envelope's binding to its KEM ciphertext meaningful, and it currently
// relies on kemCt being the last, unprefixed field — a property a future field could
// silently break.
func FuzzMlkemAAD(f *testing.F) {
	f.Add([]byte(nil), []byte(nil))
	f.Add([]byte("a"), []byte("b"))
	f.Add([]byte(mlkemAADContext), []byte(""))
	f.Add(bytes.Repeat([]byte{0}, 1088), bytes.Repeat([]byte{0}, 1088))

	f.Fuzz(func(t *testing.T, kemCtA, kemCtB []byte) {
		aadA, aadB := mlkemAAD(kemCtA), mlkemAAD(kemCtB)

		if !bytes.HasPrefix(aadA, []byte(mlkemAADContext)) {
			t.Fatalf("mlkemAAD output is not domain-separated by %q", mlkemAADContext)
		}
		if bytes.Equal(aadA, aadB) != bytes.Equal(kemCtA, kemCtB) {
			t.Fatalf("mlkemAAD is not injective: kemCt %q and %q collide", kemCtA, kemCtB)
		}
	})
}

// FuzzParseMLKEMEnvelope drives the real envelope parser from the ML-KEM decrypt path with
// arbitrary bytes. Unlike FuzzMLKEMEnvelopeAADBinding, which reconstructs the layout in the
// test, this calls the function decryptMLKEMWithContext actually uses.
//
// The property asserted is that the split is lossless: whatever parseMLKEMEnvelope accepts,
// formatMLKEMEnvelope must rebuild byte for byte. That is what rules out a nonce/sealed split
// that silently drops or duplicates bytes.
func FuzzParseMLKEMEnvelope(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(bytes.Repeat([]byte{0x07}, mlkemNonceSize-1)) // one byte short
	f.Add(bytes.Repeat([]byte{0x07}, mlkemNonceSize))   // nonce only, empty sealed
	f.Add(bytes.Repeat([]byte{0x07}, mlkemNonceSize+16+32))

	f.Fuzz(func(t *testing.T, envelope []byte) {
		nonce, sealed, err := parseMLKEMEnvelope(envelope)
		if err != nil {
			if len(envelope) >= mlkemNonceSize {
				t.Fatalf("parseMLKEMEnvelope rejected a %d-byte envelope that meets the %d-byte minimum: %v", len(envelope), mlkemNonceSize, err)
			}
			return
		}
		if len(envelope) < mlkemNonceSize {
			t.Fatalf("parseMLKEMEnvelope accepted a %d-byte envelope, under the %d-byte minimum", len(envelope), mlkemNonceSize)
		}
		if len(nonce) != mlkemNonceSize {
			t.Fatalf("parseMLKEMEnvelope returned a %d-byte nonce, want %d", len(nonce), mlkemNonceSize)
		}
		if got := formatMLKEMEnvelope(nonce, sealed); !bytes.Equal(got, envelope) {
			t.Fatalf("parse/format round-trip is lossy: got %d bytes, want the original %d", len(got), len(envelope))
		}
	})
}

// FuzzMLKEMEnvelopeAADBinding exercises the ML-KEM envelope layout that
// decryptMLKEMWithContext parses — nonce || AES-GCM(seed) with mlkemAAD(kemCt) as AAD —
// without needing an HSM, by standing in a fixed derived key for the KDF output.
//
// It asserts the property the format is meant to provide: an envelope opens under its own
// KEM ciphertext and never under a different one.
func FuzzMLKEMEnvelopeAADBinding(f *testing.F) {
	f.Add([]byte("dek-seed"), []byte("kem-ct"), []byte("other-kem-ct"))
	f.Add([]byte(nil), []byte(nil), []byte("x"))

	derivedKey := bytes.Repeat([]byte{0x2a}, 32) // stands in for crypto11.MLKEMDeriveKey output
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		f.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		f.Fatalf("cipher.NewGCM: %v", err)
	}

	f.Fuzz(func(t *testing.T, seed, kemCt, otherKemCt []byte) {
		nonce := bytes.Repeat([]byte{0x07}, mlkemNonceSize)
		envelope := append(append([]byte{}, nonce...), aead.Seal(nil, nonce, seed, mlkemAAD(kemCt))...)

		if len(envelope) < mlkemNonceSize {
			t.Fatalf("envelope of %d bytes is shorter than the %d-byte nonce", len(envelope), mlkemNonceSize)
		}
		gotNonce, sealed := envelope[:mlkemNonceSize], envelope[mlkemNonceSize:]

		opened, err := aead.Open(nil, gotNonce, sealed, mlkemAAD(kemCt))
		if err != nil {
			t.Fatalf("envelope failed to open under its own kem-ciphertext: %v", err)
		}
		if !bytes.Equal(opened, seed) {
			t.Fatalf("round-trip mismatch: got %q, want %q", opened, seed)
		}

		if bytes.Equal(kemCt, otherKemCt) {
			return
		}
		if _, err := aead.Open(nil, gotNonce, sealed, mlkemAAD(otherKemCt)); err == nil {
			t.Fatalf("envelope opened under a substituted kem-ciphertext %q", otherKemCt)
		}
	})
}
