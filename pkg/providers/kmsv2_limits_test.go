// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package providers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/eclipse-keypont/gose"
	"github.com/eclipse-keypont/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	k8skmsv2 "k8s.io/kms/apis/v2"
)

// TestEncryptResponseFitsKMSv2CiphertextLimit checks that the JWE this plugin returns as
// EncryptResponse.Ciphertext stays inside the 1 kB budget api.proto allows, across the whole
// range of key identifiers a valid configuration can produce.
//
// The size driver is the kid embedded in the JWE protected header, and it differs per algorithm
// family: the AES-GCM path passes the CKA_LABEL (up to maxCkaLabelLen), the AES-CBC path passes
// the hex CKA_ID (up to maxCkaIDHexLen). The largest legal identifier is therefore the worst
// case, and it is the case nobody tests by hand.
//
// The plaintext is a 32-byte DEK seed because that is what KMS v2 actually sends — the API
// server encrypts the object locally and hands the plugin only the key.
//
// Only the AES-GCM encryptor is exercised: the AES-CBC path needs an HSM-backed
// crypto11.BlockModeCloser, so it cannot be built here. The maxCkaIDHexLen case below stands in
// for it by driving the GCM encryptor at the kid length AES-CBC uses, which measures the header
// cost that dominates the size. A real AES-CBC JWE adds block padding and a 32-byte HMAC tag
// where GCM has a 16-byte tag — on the order of 50 more bytes, well inside the budget, but
// covering it exactly needs an integration test against a token.
func TestEncryptResponseFitsKMSv2CiphertextLimit(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	cases := []struct {
		name   string
		kidLen int
	}{
		{"typical 8-char CKA_LABEL", 8},
		{"64-char CKA_LABEL", 64},
		{"CKA_LABEL at PKCS#11 maximum (AES-GCM path)", maxCkaLabelLen},
		{"hex CKA_ID at PKCS#11 maximum (AES-CBC path)", maxCkaIDHexLen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 32 bytes = aestransformer.MinSeedSizeExtendedNonceGCM, the KMS v2 DEK seed size.
			plaintext := make([]byte, 32)

			aek, err := gose.NewAesGcmCryptor(aead, rand.Reader, strings.Repeat("L", tc.kidLen), jose.AlgA256GCM, kekKeyOps)
			require.NoError(t, err)

			jwe, err := gose.NewJweDirectEncryptorAead(aek, false).Encrypt(plaintext, nil)
			require.NoError(t, err)

			t.Logf("kid=%d chars -> EncryptResponse.Ciphertext = %d bytes (limit %d)", tc.kidLen, len(jwe), maxKMSv2CiphertextSize)
			assert.Less(t, len(jwe), maxKMSv2CiphertextSize,
				"EncryptResponse.Ciphertext must stay under the KMS v2 1 kB limit; the API server rejects the object otherwise")
		})
	}
}

// TestMaxCiphertextSizeMatchesKMSv2 pins the decrypt guard to the protocol bound. api.proto
// requires EncryptResponse.ciphertext to be less than 1 kB, and DecryptRequest.Ciphertext is
// that same value returned, so the guard must not drift above it.
func TestMaxCiphertextSizeMatchesKMSv2(t *testing.T) {
	assert.Equal(t, 1024, maxKMSv2CiphertextSize,
		"maxKMSv2CiphertextSize must track the 1 kB EncryptResponse.ciphertext limit in k8s.io/kms apis/v2/api.proto")
}

// TestMaxPlaintextSizeCannotExceedCiphertextLimit guards the consistency of the two inbound
// bounds against each other. Encryption only grows the payload, so a plaintext budget above the
// ciphertext budget describes a request this plugin would accept, encrypt, and then be unable
// to hand back — the API server would reject the response, and a later Decrypt of the same
// bytes would trip maxKMSv2CiphertextSize in UnaryInterceptor.
func TestMaxPlaintextSizeCannotExceedCiphertextLimit(t *testing.T) {
	assert.LessOrEqual(t, maxPlaintextSize, maxKMSv2CiphertextSize,
		"an accepted plaintext must be able to produce an acceptable ciphertext")
}

// TestValidateEncryptResponseCiphertext covers the outbound check that makes the bound above
// sufficient rather than merely necessary.
func TestValidateEncryptResponseCiphertext(t *testing.T) {
	cases := []struct {
		name    string
		size    int
		wantErr string
	}{
		{"empty", 0, "is empty"},
		{"typical JWE", 147, ""},
		{"at the KMS v2 limit", maxKMSv2CiphertextSize, ""},
		{"one byte over", maxKMSv2CiphertextSize + 1, "exceeds the KMS v2 maximum"},
		{"JWE for an 8 KB plaintext, the old maxPlaintextSize", 11027, "exceeds the KMS v2 maximum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEncryptResponseCiphertext(make([]byte, tc.size))
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestWorstCasePlaintextFitsCiphertextBudget checks the two inbound bounds are compatible at
// their extremes: the largest plaintext this plugin accepts, under the longest kid a valid
// configuration can carry, must still produce a ciphertext within maxKMSv2CiphertextSize.
//
// This is what makes maxPlaintextSize a real guarantee rather than a hopeful number. If a future
// change widens the plaintext budget or the PKCS#11 identifier bounds past what 1 kB can hold,
// this fails before the API server starts rejecting objects.
func TestWorstCasePlaintextFitsCiphertextBudget(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	// maxCkaIDHexLen is the longer of the two kid sources (AES-CBC); maxCkaLabelLen is AES-GCM's.
	for _, kidLen := range []int{maxCkaLabelLen, maxCkaIDHexLen} {
		aek, err := gose.NewAesGcmCryptor(aead, rand.Reader, strings.Repeat("L", kidLen), jose.AlgA256GCM, kekKeyOps)
		require.NoError(t, err)

		jwe, err := gose.NewJweDirectEncryptorAead(aek, false).Encrypt(make([]byte, maxPlaintextSize), nil)
		require.NoError(t, err)

		t.Logf("plaintext=%d (max) kid=%d (max) -> ciphertext=%d, budget %d", maxPlaintextSize, kidLen, len(jwe), maxKMSv2CiphertextSize)
		assert.NoError(t, validateEncryptResponseCiphertext([]byte(jwe)),
			"maxPlaintextSize must be small enough that even the longest kid stays in budget")
	}
}

// TestValidateEncryptResponseAnnotations covers the shared annotation budget, including the
// property that trips people up: keys count toward the total alongside values, and the limit is
// across all annotations rather than per annotation.
func TestValidateEncryptResponseAnnotations(t *testing.T) {
	// A key of exactly this length lets the cases below hit the boundary precisely.
	const key = KemCiphertextAnnotationKey

	cases := []struct {
		name        string
		annotations map[string][]byte
		wantErr     bool
	}{
		{"nil", nil, false},
		{"empty", map[string][]byte{}, false},
		{
			name:        "ML-KEM-1024 KEM ciphertext, the largest this plugin emits",
			annotations: map[string][]byte{key: make([]byte, 1568)},
		},
		{
			name:        "total exactly at the limit",
			annotations: map[string][]byte{key: make([]byte, maxKMSv2AnnotationsSize-len(key))},
		},
		{
			name:        "total one byte over the limit",
			annotations: map[string][]byte{key: make([]byte, maxKMSv2AnnotationsSize-len(key)+1)},
			wantErr:     true,
		},
		{
			// Each value alone is legal; together they are not. This is what "shared budget" means.
			name: "two annotations each under the limit but over it combined",
			annotations: map[string][]byte{
				KemCiphertextAnnotationKey:   make([]byte, maxKMSv2AnnotationsSize*2/3),
				AlgorithmFamilyAnnotationKey: make([]byte, maxKMSv2AnnotationsSize*2/3),
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEncryptResponseAnnotations(tc.annotations)
			if !tc.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "exceeds the KMS v2 maximum")
		})
	}
}

// TestAnnotationsTotalSizeCountsKeysAndValues pins the measurement itself against the API
// server's rule (totalSize += len(k) + len(v)). Counting values only would understate the total
// by ~50 bytes per annotation here, since this plugin's keys are FQDNs.
func TestAnnotationsTotalSizeCountsKeysAndValues(t *testing.T) {
	annotations := map[string][]byte{
		KemCiphertextAnnotationKey:   make([]byte, 1088),
		AlgorithmFamilyAnnotationKey: []byte("ml-kem"),
	}

	valuesOnly := 1088 + len("ml-kem")
	want := valuesOnly + len(KemCiphertextAnnotationKey) + len(AlgorithmFamilyAnnotationKey)

	assert.Equal(t, want, annotationsTotalSize(annotations))
	assert.Greater(t, annotationsTotalSize(annotations), valuesOnly,
		"annotation keys must count toward the budget, not just values")
}

// TestRealMLKEMAnnotationsFitBudget checks the actual annotations the ML-KEM path emits, at the
// largest parameter set, leave the budget with room to spare.
func TestRealMLKEMAnnotationsFitBudget(t *testing.T) {
	// ML-KEM-512 / 768 / 1024 KEM ciphertext sizes per FIPS 203.
	for _, kemCtSize := range []int{768, 1088, 1568} {
		resp := &k8skmsv2.EncryptResponse{}
		putEncapsulation(resp, make([]byte, kemCtSize))
		putAlgorithmFamily(resp, AlgMLKEM)

		total := annotationsTotalSize(resp.Annotations)
		t.Logf("kemCt=%d bytes -> annotations total %d bytes, budget %d", kemCtSize, total, maxKMSv2AnnotationsSize)
		assert.NoError(t, validateEncryptResponseAnnotations(resp.Annotations))
	}
}
