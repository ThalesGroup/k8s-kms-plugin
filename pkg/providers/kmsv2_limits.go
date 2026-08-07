// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package providers

import "fmt"

// Size and length limits, named by a single rule so the unit is never in doubt:
//
//	maxKMSv2<Field>Size  a limit KMS v2 imposes; always BYTES on the wire, per api.proto
//	                     and the API server's envelope validation.
//	max<Attr>Size        a PKCS#11 attribute limit measured in BYTES.
//	max<Attr>HexLen      a PKCS#11 attribute limit measured in HEX CHARACTERS, which is
//	                     twice the raw byte count.
//	maxPlaintextSize     this plugin's own guard, in BYTES; KMS v2 sets none, so it
//	                     deliberately carries no maxKMSv2 prefix.
//
// The hex/raw distinction is the one that bites: a CKA_ID is raw bytes on the token but travels
// as a hex string through the CLI and through every KMS v2 KeyId field, where it takes twice the
// space. Anything named *HexLen counts characters of that string; everything named *Size counts
// bytes. Because the string is ASCII hex, one hex character is exactly one byte on the wire,
// which is what lets a *HexLen and a maxKMSv2*Size be compared directly.
const (
	// maxCkaIDHexLen bounds a PKCS#11 CKA_ID in HEX CHARACTERS, the form used by --p11-key-id and
	// by KeyId fields: 510 hex characters, encoding 255 raw CKA_ID bytes, occupying 510 bytes as
	// a KeyId string.
	// PKCS#11 has no maximum size limit for CKA_ID but most implementation have a limit.
	maxCkaIDHexLen = 510
	// maxCkaLabelSize bounds a PKCS#11 CKA_LABEL in BYTES. A label is UTF-8 text, never hex, so
	// there is no doubling here — 255 means 255 bytes.
	maxCkaLabelSize = 255
	// kmsv2DEKSeedSize is the size in BYTES of what the API server actually sends as
	// EncryptRequest.Plaintext: it encrypts the object itself with a local DEK and passes this
	// plugin only that key (aestransformer.MinSeedSizeExtendedNonceGCM).
	kmsv2DEKSeedSize = 32
	// maxPlaintextSize bounds EncryptRequest.Plaintext in BYTES. KMSv2 api.proto sets no limit, so
	// this is 4x the real payload — slack for a future, longer DEK seed without accepting anything
	// whose ciphertext could breach maxKMSv2CiphertextSize.
	maxPlaintextSize = 4 * kmsv2DEKSeedSize
	// maxKMSv2CiphertextSize bounds DecryptRequest.Ciphertext in BYTES. KMSv2 api.proto requires
	// EncryptResponse.ciphertext to be non-empty and under 1 kB, enforced by the API server's
	// ValidateEncryptedObject; Decrypt receives that same value back, so nothing larger can exist.
	// Ciphertext is raw bytes on the wire — no hex encoding is involved.
	maxKMSv2CiphertextSize = 1024
	// maxKMSv2AnnotationsSize bounds EncryptResponse.Annotations in BYTES, mirroring
	// annotationsMaxSize in k8s.io/apiserver (pkg/storage/value/encrypt/envelope/kmsv2).
	//
	// The budget is shared: the API server sums len(key)+len(value) across every annotation and
	// rejects the object when that total exceeds this. It is not a per-annotation limit, so
	// adding a second annotation eats into the first one's headroom. Annotation values are raw
	// bytes — no hex encoding — but the keys count toward the total too, and this plugin's keys
	// are ~50-byte FQDNs (the API server requires a fully qualified domain name).
	maxKMSv2AnnotationsSize = 32 * 1024
	// maxKMSv2KeyIDSize bounds EncryptResponse.KeyId and StatusResponse.KeyId in BYTES, mirroring
	// KeyIDMaxSize in k8s.io/apiserver (pkg/storage/value/encrypt/envelope/kmsv2), whose
	// ValidateKeyID measures len(keyID) on the string.
	//
	// Mind the encoding: this plugin's KeyId is a hex-encoded CKA_ID, so 1024 BYTES of KeyId is
	// 1024 hex characters, which encodes only a 512-byte raw CKA_ID. maxCkaIDHexLen (510 hex
	// characters, 255 raw bytes) is the stricter bound and rejects first on every operator-facing
	// path; only a CKA_ID read from the token can reach this one, since PKCS#11 sets no length
	// limit of its own. validateKMSv2KeyID covers that path.
	maxKMSv2KeyIDSize = 1024
)

// Compile-time assertion that a CKA_ID accepted by validateHexKeyID can never yield a KeyId over
// the KMS v2 limit. Raising maxCkaIDHexLen beyond maxKMSv2KeyIDSize fails the build here instead
// of producing Status responses the API server rejects at runtime.
//
// Comparing a hex-character count against a byte limit is sound only because the KeyId string is
// ASCII hex: a CKA_ID of maxCkaIDHexLen hex characters occupies exactly that many bytes on the
// wire. Do not restate either constant in raw-CKA_ID bytes here — that would halve one side and
// silently double the bound this assertion is meant to enforce.
const _ = uint(maxKMSv2KeyIDSize - maxCkaIDHexLen)

// validateEncryptResponseCiphertext enforces the EncryptResponse.ciphertext contract from
// KMSv2 api.proto: non-empty and within maxKMSv2CiphertextSize.
//
// Bounding the plaintext is not sufficient on its own — the JWE header carries a kid (CKA_LABEL
// for AES-GCM, hex CKA_ID for AES-CBC), so ciphertext size also grows with the operator's key
// naming. Checking the finished bytes covers every configuration, and turns what would surface
// as an API server rejection into an error that names the cause here.
func validateEncryptResponseCiphertext(ciphertext []byte) error {
	if len(ciphertext) == 0 {
		return fmt.Errorf("EncryptResponse ciphertext is empty")
	}
	if len(ciphertext) > maxKMSv2CiphertextSize {
		return fmt.Errorf("EncryptResponse ciphertext is %d bytes, which exceeds the KMS v2 maximum of %d bytes", len(ciphertext), maxKMSv2CiphertextSize)
	}
	return nil
}

// annotationsTotalSize returns the figure the k8s KMSv2 API server measures against
// maxKMSv2AnnotationsSize: the sum of every annotation's key and value length, in BYTES.
//
// Keys count toward the budget as well as values, which is easy to overlook — this plugin's keys
// are ~50-byte FQDNs, so a response carrying several small annotations spends more than the
// values alone suggest.
func annotationsTotalSize(annotations map[string][]byte) int {
	total := 0
	for k, v := range annotations {
		total += len(k) + len(v)
	}
	return total
}

// validateEncryptResponseAnnotations enforces the EncryptResponse.annotations size contract from
// KMSv2 api.proto, mirroring the API server's validateAnnotations: the combined key and value bytes
// of all annotations must not exceed maxKMSv2AnnotationsSize.
//
// The ML-KEM path is the one with real content here — its KEM ciphertext is 768, 1088 or 1568
// bytes for ML-KEM-512/768/1024 — so the budget is nowhere near tight today. The check exists so
// that stays true: annotations are the natural place to add per-object metadata, and the limit
// is shared across all of them.
//
// Key format is left to the API server. It requires a fully qualified domain name, which the
// package-level annotation key constants already satisfy; they are compile-time values, not
// anything an operator or request can influence.
func validateEncryptResponseAnnotations(annotations map[string][]byte) error {
	if total := annotationsTotalSize(annotations); total > maxKMSv2AnnotationsSize {
		return fmt.Errorf("EncryptResponse annotations total %d bytes across %d annotation(s) (keys plus values), which exceeds the KMS v2 maximum of %d bytes",
			total, len(annotations), maxKMSv2AnnotationsSize)
	}
	return nil
}

// validateKMSv2KeyID checks that a hex-encoded CKA_ID is usable as a KMS v2 KeyId, applying the
// API server's own rule so a mismatch surfaces at plugin startup rather than as a rejected
// Status response once the API server connects.
//
// hexKeyID is the KeyId exactly as it goes on the wire, so len() is simultaneously its size in
// BYTES (what maxKMSv2KeyIDSize bounds) and its length in HEX CHARACTERS; the raw CKA_ID it
// encodes is half that. The error spells all three out so nobody has to re-derive which is meant.
func validateKMSv2KeyID(hexKeyID string) error {
	if len(hexKeyID) == 0 {
		return fmt.Errorf("KMS v2 KeyId is empty")
	}
	if len(hexKeyID) > maxKMSv2KeyIDSize {
		return fmt.Errorf("KMS v2 KeyId is %d bytes (%d hex characters encoding a %d-byte CKA_ID), which exceeds the Kubernetes API server maximum of %d bytes",
			len(hexKeyID), len(hexKeyID), len(hexKeyID)/2, maxKMSv2KeyIDSize)
	}
	return nil
}

// validateHexKeyID checks that a hex-encoded CKA_ID string is non-empty, even-length, and
// within maxCkaIDHexLen HEX CHARACTERS (not raw bytes) before hex decoding.
func validateHexKeyID(hexKeyID string) error {
	if len(hexKeyID) == 0 {
		return fmt.Errorf("hex key ID is empty")
	}
	if len(hexKeyID)%2 != 0 {
		return fmt.Errorf("hex key ID must have an even number of characters, got %d", len(hexKeyID))
	}
	if len(hexKeyID) > maxCkaIDHexLen {
		return fmt.Errorf("hex key ID is %d hex characters (%d raw CKA_ID bytes), which exceeds PKCS#11 maximum of %d hex characters", len(hexKeyID), len(hexKeyID)/2, maxCkaIDHexLen)
	}
	return nil
}

// validateCkaLabel checks that a CKA_LABEL string is non-empty and within maxCkaLabelSize BYTES
// (it is UTF-8 text, not hex) before it is passed to the HSM.
func validateCkaLabel(label string) error {
	if len(label) == 0 {
		return fmt.Errorf("CKA_LABEL is empty")
	}
	if len(label) > maxCkaLabelSize {
		return fmt.Errorf("CKA_LABEL length %d exceeds PKCS#11 maximum of %d bytes", len(label), maxCkaLabelSize)
	}
	return nil
}
