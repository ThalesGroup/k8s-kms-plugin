// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package providers

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/jose"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	k8skmsv2 "k8s.io/kms/apis/v2"
)

// TestValidateHexKeyID covers all branches of the standalone validator.
func TestValidateHexKeyID(t *testing.T) {
	tooLong := strings.Repeat("a", maxCkaIDHexLen+2) // even length, over limit
	atLimit := strings.Repeat("a", maxCkaIDHexLen)

	cases := []struct {
		name    string
		input   string
		wantErr string // substring; empty means no error expected
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "abc", "even number of characters"},
		{"too long", tooLong, "exceeds PKCS#11 maximum"},
		{"valid short", "abcd", ""},
		{"valid single byte", "00", ""},
		{"at limit", atLimit, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHexKeyID(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// Tests for P11 struct methods
func TestP11_SetKekKeyIdString(t *testing.T) {
	p := &P11{}

	hexKeyID := "abcd1234"
	err := p.SetKekKeyIDString(hexKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexKeyID)
	assert.Equal(t, expected, p.kekCkaID)
}

func TestP11_SetKekKeyIdString_Validation(t *testing.T) {
	tooLong := strings.Repeat("a", maxCkaIDHexLen+2) // even length, over limit
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "abc", "even number of characters"},
		{"too long", tooLong, "exceeds PKCS#11 maximum"},
		{"invalid hex chars even length", "zzzz", "invalid hex KeyID"},
		{"valid", "abcd1234", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetKekKeyIDString(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestP11_SetHmacKeyIdString_Validation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "a", "even number of characters"},
		{"valid", "ef567890", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetHmacKeyIDString(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestP11_SetOldHmacKeyIdString_Validation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "a", "even number of characters"},
		{"valid", "1234abcd", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetOldHmacKeyIDString(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestP11_SetOldKekKeyIdString_Validation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "hex key ID is empty"},
		{"odd length", "a", "even number of characters"},
		{"valid", "5678cdef", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &P11{}
			err := p.SetOldKekKeyIDString(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestP11_DecryptWithContext_InvalidKeyId verifies that validateHexKeyID is enforced
// on the DecryptRequest.KeyId when the decryptor is not yet cached.
func TestP11_DecryptWithContext_InvalidKeyId(t *testing.T) {
	p := &P11{
		kekCkaID:        []byte{0x01},
		algorithmFamily: AlgAESGCM,
		decryptors:      map[string]gose.JweDecryptor{},
	}

	cases := []struct {
		name  string
		keyID string
	}{
		{"empty key ID", ""},
		{"odd length key ID", "abc"},
		{"oversized key ID", strings.Repeat("a", maxCkaIDHexLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &k8skmsv2.DecryptRequest{
				KeyId:      tc.keyID,
				Ciphertext: []byte("mock"),
			}
			_, err := p.decryptWithContext(req, false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid key ID")
		})
	}
}

func TestP11_GetKekKeyIdString(t *testing.T) {
	p := &P11{
		kekCkaID: []byte{0xab, 0xcd, 0x12, 0x34},
	}

	result := p.GetKekKeyIDString()

	assert.Equal(t, "abcd1234", result)
}

func TestP11_GetKekCkaLabelByteA(t *testing.T) {
	p := &P11{
		kekCkaLabel: "test-label",
	}

	result := p.GetKekCkaLabelByteA()

	assert.Equal(t, []byte("test-label"), result)
}

func TestP11_SetHmacKeyIdString(t *testing.T) {
	p := &P11{}

	hexHmacKeyID := "ef567890"
	err := p.SetHmacKeyIDString(hexHmacKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexHmacKeyID)
	assert.Equal(t, expected, p.hmacCkaID)
}

func TestP11_GetHmacKeyIdString(t *testing.T) {
	p := &P11{
		hmacCkaID: []byte{0xef, 0x56, 0x78, 0x90},
	}

	result := p.GetHmacKeyIDString()

	assert.Equal(t, "ef567890", result)
}

func TestP11_SetOldHmacKeyIdString(t *testing.T) {
	p := &P11{}

	hexOldHmacKeyID := "1234abcd"
	err := p.SetOldHmacKeyIDString(hexOldHmacKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexOldHmacKeyID)
	assert.Equal(t, expected, p.oldHmacCkaID)
}

func TestP11_SetOldKekKeyIdString(t *testing.T) {
	p := &P11{}

	hexOldKeyID := "5678cdef"
	err := p.SetOldKekKeyIDString(hexOldKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexOldKeyID)
	assert.Equal(t, expected, p.oldKekCkaID)
}

// Tests for Status method
func TestP11_Status_Success(t *testing.T) {
	p := &P11{
		kekCkaID: []byte{0x12, 0x34, 0x56, 0x78},
	}

	ctx := context.Background()
	req := &k8skmsv2.StatusRequest{}

	resp, err := p.Status(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "v2", resp.Version)
	assert.Equal(t, "ok", resp.Healthz)
	assert.Equal(t, "12345678", resp.KeyId)
}

func TestP11_Status_NilKekId(t *testing.T) {
	p := &P11{
		kekCkaID: nil,
	}

	ctx := context.Background()
	req := &k8skmsv2.StatusRequest{}

	_, err := p.Status(ctx, req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "KEK ID is nil")
}

func TestP11_Status_EmptyKekId(t *testing.T) {
	p := &P11{
		kekCkaID: []byte{},
	}

	ctx := context.Background()
	req := &k8skmsv2.StatusRequest{}

	_, err := p.Status(ctx, req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "KEK ID is empty")
}

// Create a mock JWE with a valid IV
var validJWEs = []string{
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9..RCs4v0hOW9lHFwDOo7itNA.encrypted_data.tag",
}

// Tests for getIVFromDecryptRequest function
func TestP11_GetIVFromDecryptRequest_ValidIV(t *testing.T) {

	for _, mockJWE := range validJWEs {
		t.Run(mockJWE, func(t *testing.T) {
			// Expected IV
			realIv, err := base64.RawURLEncoding.DecodeString("RCs4v0hOW9lHFwDOo7itNA")
			assert.NoError(t, err)

			req := &k8skmsv2.DecryptRequest{
				Ciphertext: []byte(mockJWE),
			}

			// get IV from DecryptRequest
			iv, err := getIVFromDecryptRequest(req)

			// Expect no error
			assert.NoError(t, err)
			assert.Equalf(t, realIv, iv, "getIVFromDecryptRequest() = %v, want %v", iv, realIv)
		})
	}
}

// a list of invalid JWEs, with a focus on the invalid IV
var invalidJWEs = []string{
	// Invalid base64 encoding
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9..!.encrypted_data.tag",

	// Missing IV segment
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9.encrypted_data.tag",

	// Invalid JSON structure
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9..IV..encrypted_data.tag",

	// missing IV (empty IV segment)
	"eyJhbGciOiJBMjU2Q0JDIiwia2lkIjoiNjQ2MzYxMzgzNTM5MzEzMjYzNjMzNTY1MzczMTMyNjQiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJfdGhhbGVzX2FhZCI6IkFBQUFBQUFBQUNBIiwiZW5jIjoiQTI1NkNCQyJ9...encrypted_data.tag",

	// Empty JWE
	".....",
	"",
}

func TestP11_GetIVFromDecryptRequest_InvalidIV(t *testing.T) {
	for _, mockJWE := range invalidJWEs {
		t.Run(mockJWE, func(t *testing.T) {

			req := &k8skmsv2.DecryptRequest{
				Ciphertext: []byte(mockJWE),
			}

			// get IV from DecryptRequest
			_, err := getIVFromDecryptRequest(req)

			// Expect an error since the IV is invalid
			assert.Error(t, err)
		})
	}
}

func TestP11_NewP11_AllEmptyArgs(t *testing.T) {

	emptyActiveCfg := &crypto11.Config{}
	emptyOldCfg := &crypto11.Config{}

	_, err := NewP11(emptyActiveCfg, false, "", "", "", "", "", false, emptyOldCfg, "", "", "", "", "")
	assert.Error(t, err)
}

// TestAlgSentinelValues verifies that all routing sentinels carry the expected
// slug strings. Changing these values would break backwards-compatible config files.
func TestAlgSentinelValues(t *testing.T) {
	assert.Equal(t, jose.Alg("aes-gcm"), AlgAESGCM)
	assert.Equal(t, jose.Alg("aes-cbc"), AlgAESCBC)
	assert.Equal(t, jose.Alg("rsa-oaep"), AlgRSAOAEP)
	assert.Equal(t, jose.Alg("ml-kem"), AlgMLKEM)
}

// TestIsPKCS11AuthenticationError covers nil, non-pkcs11, and CKR_PIN_INCORRECT inputs.
func TestIsPKCS11AuthenticationError(t *testing.T) {
	assert.False(t, IsPKCS11AuthenticationError(nil))
	assert.False(t, IsPKCS11AuthenticationError(errors.New("plain error")))

	// Wrap a pkcs11.Error so errors.Unwrap returns it.
	pinErr := fmt.Errorf("login: %w", pkcs11.Error(pkcs11.CKR_PIN_INCORRECT))
	assert.True(t, IsPKCS11AuthenticationError(pinErr))

	otherErr := fmt.Errorf("login: %w", pkcs11.Error(pkcs11.CKR_GENERAL_ERROR))
	assert.False(t, IsPKCS11AuthenticationError(otherErr))
}

// TestPutEncapsulation_NilAnnotations covers the common case: a freshly built
// EncryptResponse with a nil Annotations map must be lazily initialized.
func TestPutEncapsulation_NilAnnotations(t *testing.T) {
	resp := &k8skmsv2.EncryptResponse{}
	ct := []byte{0x01, 0x02, 0x03}

	putEncapsulation(resp, ct)

	require.NotNil(t, resp.Annotations)
	assert.Equal(t, ct, resp.Annotations[KemCTAnnotationKey])
	assert.Len(t, resp.Annotations, 1, "putEncapsulation must not touch any other annotation key")
}

// TestPutEncapsulation_ExistingAnnotations covers a pre-populated Annotations map: the
// KEM ciphertext must be added alongside existing entries, not replace the map.
func TestPutEncapsulation_ExistingAnnotations(t *testing.T) {
	resp := &k8skmsv2.EncryptResponse{
		Annotations: map[string][]byte{"other.example.org": []byte("keep-me")},
	}
	ct := []byte{0xAA, 0xBB}

	putEncapsulation(resp, ct)

	assert.Equal(t, []byte("keep-me"), resp.Annotations["other.example.org"])
	assert.Equal(t, ct, resp.Annotations[KemCTAnnotationKey])
}

// TestGetEncapsulation_Present covers a DecryptRequest carrying the kem-ct annotation
// round-tripped from a prior Encrypt call.
func TestGetEncapsulation_Present(t *testing.T) {
	ct := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	req := &k8skmsv2.DecryptRequest{
		Annotations: map[string][]byte{KemCTAnnotationKey: ct},
	}

	got, ok := getEncapsulation(req)
	assert.True(t, ok)
	assert.Equal(t, ct, got)
}

// TestGetEncapsulation_Absent covers a DecryptRequest for an object produced by a
// classical (non-ML-KEM) algorithm family, which never carries this annotation.
func TestGetEncapsulation_Absent(t *testing.T) {
	req := &k8skmsv2.DecryptRequest{}

	got, ok := getEncapsulation(req)
	assert.False(t, ok)
	assert.Nil(t, got)
}

// TestPutAlgorithmFamily_NilAnnotations covers the common case: a freshly built
// EncryptResponse with a nil Annotations map must be lazily initialized.
func TestPutAlgorithmFamily_NilAnnotations(t *testing.T) {
	resp := &k8skmsv2.EncryptResponse{}

	putAlgorithmFamily(resp, AlgMLKEM)

	require.NotNil(t, resp.Annotations)
	assert.Equal(t, []byte("ml-kem"), resp.Annotations[AlgorithmFamilyAnnotationKey])
}

// TestPutAlgorithmFamily_ExistingAnnotations covers a pre-populated Annotations map (e.g.
// one that already carries the ML-KEM kem-ct annotation): the algorithm-family entry must be
// added alongside existing entries, not replace the map.
func TestPutAlgorithmFamily_ExistingAnnotations(t *testing.T) {
	resp := &k8skmsv2.EncryptResponse{
		Annotations: map[string][]byte{KemCTAnnotationKey: {0x01, 0x02}},
	}

	putAlgorithmFamily(resp, AlgAESGCM)

	assert.Equal(t, []byte{0x01, 0x02}, resp.Annotations[KemCTAnnotationKey])
	assert.Equal(t, []byte("aes-gcm"), resp.Annotations[AlgorithmFamilyAnnotationKey])
}

// mockJweEncryptor is a no-op gose.JweEncryptor used in concurrency tests.
type mockJweEncryptor struct{}

func (m *mockJweEncryptor) Encrypt(_, _ []byte) (string, error) { return "mock.jwe.token", nil }

// mockJweDecryptor is a no-op gose.JweDecryptor used in concurrency tests.
type mockJweDecryptor struct{}

func (m *mockJweDecryptor) Decrypt(_ string) ([]byte, []byte, error) {
	return []byte("plaintext"), nil, nil
}

// TestP11_MapAccess_Race verifies that concurrent reads (Encrypt, Decrypt) and
// writes (SetEncryptors, SetDecryptors) on the encryptor/decryptor maps do not
// produce data races. Run with: go test -race ./pkg/providers/...
//
// The test avoids any HSM interaction by pre-populating the maps so that
// Encrypt and Decrypt find a cached entry and return early without calling
// into crypto11.
func TestP11_MapAccess_Race(_ *testing.T) {
	const hexID = "01"
	p := &P11{kekCkaID: []byte{0x01}}

	_ = p.SetEncryptors(map[string]gose.JweEncryptor{hexID: &mockJweEncryptor{}})
	_ = p.SetDecryptors(map[string]gose.JweDecryptor{hexID: &mockJweDecryptor{}})

	ctx := context.Background()
	encReq := &k8skmsv2.EncryptRequest{Plaintext: []byte("hello")}
	decReq := &k8skmsv2.DecryptRequest{KeyId: hexID, Ciphertext: []byte("mock.jwe.token")}

	var wg sync.WaitGroup
	const n = 50

	for i := 0; i < n; i++ {
		wg.Add(4)

		// writers: replace the whole map
		go func() {
			defer wg.Done()
			_ = p.SetEncryptors(map[string]gose.JweEncryptor{hexID: &mockJweEncryptor{}})
		}()
		go func() {
			defer wg.Done()
			_ = p.SetDecryptors(map[string]gose.JweDecryptor{hexID: &mockJweDecryptor{}})
		}()

		// readers: hit the cached-entry path — no HSM calls needed
		go func() {
			defer wg.Done()
			_, _ = p.Encrypt(ctx, encReq)
		}()
		go func() {
			defer wg.Done()
			_, _ = p.Decrypt(ctx, decReq)
		}()
	}

	wg.Wait()
}

// TestP11_SetEncryptor_Race verifies that single-entry writes (SetEncryptor,
// SetDecryptor) racing against full-map replacements (SetEncryptors,
// SetDecryptors) do not produce data races.
func TestP11_SetEncryptor_Race(_ *testing.T) {
	p := &P11{kekCkaID: []byte{0x01}}
	_ = p.SetEncryptors(map[string]gose.JweEncryptor{})
	_ = p.SetDecryptors(map[string]gose.JweDecryptor{})

	var wg sync.WaitGroup
	const n = 50

	for i := 0; i < n; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			_ = p.SetEncryptor(&mockJweEncryptor{})
		}()
		go func() {
			defer wg.Done()
			_ = p.SetEncryptors(map[string]gose.JweEncryptor{"01": &mockJweEncryptor{}})
		}()
		go func() {
			defer wg.Done()
			_ = p.SetDecryptor(&mockJweDecryptor{})
		}()
		go func() {
			defer wg.Done()
			_ = p.SetDecryptors(map[string]gose.JweDecryptor{"01": &mockJweDecryptor{}})
		}()
	}

	wg.Wait()
}

func TestP11_NewP11_ConfigEmptyArgs(t *testing.T) {

	validActiveCfg := &crypto11.Config{
		Path:       "/some/path/to/lib.so",
		TokenLabel: "label",
		Pin:        "1234",
	}
	validOldCfg := &crypto11.Config{
		Path:       "/some/path/to/oldlib.so",
		TokenLabel: "oldlabel",
		Pin:        "5678",
	}

	_, err := NewP11(validActiveCfg, false, "", "", "", "", "", false, validOldCfg, "", "", "", "", "")
	assert.Error(t, err)
}

// TestValidateCkaLabel covers all branches of the CKA_LABEL validator.
func TestValidateCkaLabel(t *testing.T) {
	atLimit := strings.Repeat("a", maxCkaLabelLen)
	overLimit := strings.Repeat("a", maxCkaLabelLen+1)
	// "é" is 2 bytes in UTF-8; len() counts bytes, not runes.
	multibyteOver := strings.Repeat("é", maxCkaLabelLen/2+1) // 128×2 = 256 bytes

	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "CKA_LABEL is empty"},
		{"at limit", atLimit, ""},
		{"over limit", overLimit, "exceeds PKCS#11 maximum"},
		{"valid short", "my-key-label", ""},
		{"multibyte over limit", multibyteOver, "exceeds PKCS#11 maximum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCkaLabel(tc.input)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestGetKeyIdAndLabel_LabelTooLong confirms that validateCkaLabel fires in
// GetKeyIDAndLabel before any HSM call is attempted.
func TestGetKeyIdAndLabel_LabelTooLong(t *testing.T) {
	p := &P11{algorithmFamily: AlgAESGCM}
	tooLong := strings.Repeat("a", maxCkaLabelLen+1)

	_, _, err := GetKeyIDAndLabel(p, "", tooLong)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds PKCS#11 maximum")
}

// noopHandler is a grpc.UnaryHandler stub that returns success without side effects.
var noopHandler grpc.UnaryHandler = func(_ context.Context, _ interface{}) (interface{}, error) {
	return nil, nil
}

// requireGRPCCode is a test helper that asserts a gRPC status code on an error.
func requireGRPCCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok, "expected a gRPC status error")
	assert.Equal(t, want, st.Code())
}

// TestUnaryInterceptor_EncryptRequest_Validation checks that empty and oversized
// plaintext are rejected before the handler is reached.
func TestUnaryInterceptor_EncryptRequest_Validation(t *testing.T) {
	p := &P11{}
	ctx := context.Background()
	info := &grpc.UnaryServerInfo{}

	cases := []struct {
		name     string
		req      *k8skmsv2.EncryptRequest
		wantCode codes.Code // codes.OK means no interceptor error expected
	}{
		{"nil plaintext", &k8skmsv2.EncryptRequest{}, codes.InvalidArgument},
		{"empty plaintext", &k8skmsv2.EncryptRequest{Plaintext: []byte{}}, codes.InvalidArgument},
		{"plaintext too large", &k8skmsv2.EncryptRequest{Plaintext: make([]byte, maxPlaintextSize+1)}, codes.InvalidArgument},
		{"valid plaintext", &k8skmsv2.EncryptRequest{Plaintext: []byte("hello")}, codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.UnaryInterceptor(ctx, tc.req, info, noopHandler)
			if tc.wantCode == codes.OK {
				assert.NoError(t, err)
			} else {
				requireGRPCCode(t, err, tc.wantCode)
			}
		})
	}
}

// TestUnaryInterceptor_DecryptRequest_Validation checks that missing key ID,
// empty ciphertext, and oversized ciphertext are rejected before the handler.
func TestUnaryInterceptor_DecryptRequest_Validation(t *testing.T) {
	p := &P11{kekCkaID: []byte{0x01}}
	ctx := context.Background()
	info := &grpc.UnaryServerInfo{}
	validKeyID := p.GetKekKeyIDString()

	cases := []struct {
		name     string
		req      *k8skmsv2.DecryptRequest
		wantCode codes.Code
	}{
		{"empty key ID", &k8skmsv2.DecryptRequest{KeyId: "", Ciphertext: []byte("data")}, codes.InvalidArgument},
		{"empty ciphertext", &k8skmsv2.DecryptRequest{KeyId: validKeyID, Ciphertext: []byte{}}, codes.InvalidArgument},
		{"ciphertext too large", &k8skmsv2.DecryptRequest{KeyId: validKeyID, Ciphertext: make([]byte, maxCiphertextSize+1)}, codes.InvalidArgument},
		{"valid request", &k8skmsv2.DecryptRequest{KeyId: validKeyID, Ciphertext: []byte("mock")}, codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.UnaryInterceptor(ctx, tc.req, info, noopHandler)
			if tc.wantCode == codes.OK {
				assert.NoError(t, err)
			} else {
				requireGRPCCode(t, err, tc.wantCode)
			}
		})
	}
}
