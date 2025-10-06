/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package providers

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose/jose"
	"github.com/stretchr/testify/assert"

	k8skmsv2 "k8s.io/kms/apis/v2"
)

// Tests for P11 struct methods
func TestP11_SetKekKeyIdString(t *testing.T) {
	p := &P11{}

	hexKeyID := "abcd1234"
	err := p.SetKekKeyIdString(hexKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexKeyID)
	assert.Equal(t, expected, p.kekCkaId)
}

func TestP11_SetKekKeyIdString_InvalidHex(t *testing.T) {
	p := &P11{}

	err := p.SetKekKeyIdString("invalid_hex")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hex KeyID")
}

func TestP11_GetKekKeyIdString(t *testing.T) {
	p := &P11{
		kekCkaId: []byte{0xab, 0xcd, 0x12, 0x34},
	}

	result := p.GetKekKeyIdString()

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
	err := p.SetHmacKeyIdString(hexHmacKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexHmacKeyID)
	assert.Equal(t, expected, p.hmacCkaId)
}

func TestP11_GetHmacKeyIdString(t *testing.T) {
	p := &P11{
		hmacCkaId: []byte{0xef, 0x56, 0x78, 0x90},
	}

	result := p.GetHmacKeyIdString()

	assert.Equal(t, "ef567890", result)
}

func TestP11_SetOldHmacKeyIdString(t *testing.T) {
	p := &P11{}

	hexOldHmacKeyID := "1234abcd"
	err := p.SetOldHmacKeyIdString(hexOldHmacKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexOldHmacKeyID)
	assert.Equal(t, expected, p.oldHmacCkaId)
}

func TestP11_SetOldKekKeyIdString(t *testing.T) {
	p := &P11{}

	hexOldKeyID := "5678cdef"
	err := p.SetOldKekKeyIdString(hexOldKeyID)

	assert.NoError(t, err)
	expected, _ := hex.DecodeString(hexOldKeyID)
	assert.Equal(t, expected, p.oldKekCkaId)
}

// Tests for Status method
func TestP11_Status_Success(t *testing.T) {
	p := &P11{
		kekCkaId: []byte{0x12, 0x34, 0x56, 0x78},
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
		kekCkaId: nil,
	}

	ctx := context.Background()
	req := &k8skmsv2.StatusRequest{}

	_, err := p.Status(ctx, req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "KEK ID is nil")
}

func TestP11_Status_EmptyKekId(t *testing.T) {
	p := &P11{
		kekCkaId: []byte{},
	}

	ctx := context.Background()
	req := &k8skmsv2.StatusRequest{}

	_, err := p.Status(ctx, req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "KEK ID is empty")
}

// Tests for genKekKid method
func TestP11_genKekKid(t *testing.T) {
	p := &P11{}

	kid, err := p.genKekKid()

	assert.NoError(t, err)
	assert.NotNil(t, kid)
	assert.Greater(t, len(kid), 0)

	// Verify it's a valid UUID text format
	_, err = uuid.ParseBytes(kid)
	assert.NoError(t, err)
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

// Test for unknown algorithm in map
func TestP11_AlgToKeyGenParams_UnknownAlgorithm(t *testing.T) {
	_, exists := algToKeyGenParams[jose.Alg("unknown")]
	assert.False(t, exists)
}

func TestP11_NewP11_AllEmptyArgs(t *testing.T) {

	emptyActiveCfg := &crypto11.Config{}
	emptyOldCfg := &crypto11.Config{}

	_, err := NewP11(emptyActiveCfg, false, "", "", "", "", "", false, emptyOldCfg, "", "", "", "", "")
	assert.Error(t, err)
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
