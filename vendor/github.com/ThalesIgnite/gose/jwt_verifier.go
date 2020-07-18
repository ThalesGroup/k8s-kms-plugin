// Copyright 2019 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package gose

import (
	"fmt"
	"time"

	"github.com/ThalesIgnite/gose/jose"
)

// JwtVerifierImpl implements the JWT Verification API
type JwtVerifierImpl struct {
	store TrustStore
}

// Verify the jwt and audience is valid
func (verifier *JwtVerifierImpl) Verify(jwt string, audience []string) (kid string, claims *jose.JwtClaims, err error) {
	var token jose.Jwt
	var signed string
	if signed, err = token.Unmarshal(jwt); err != nil {
		return
	}
	now := time.Now().Unix()
	seen := []string{}
	if token.Claims.NotBefore > now {
		err = ErrInvalidJwtTimeframe
		return
	}
	if token.Claims.Expiration <= now {
		err = ErrInvalidJwtTimeframe
		return
	}
	if len(token.Claims.Audiences.Aud) == 0 || len(audience) == 0 {
		err = &InvalidFormat{fmt.Sprintf("no expected audience | expected %s | seen %s", audience, seen)}
		return
	}

	// For debugging you may want to see the details of the expected and observed audiences
	// Check at least 1 audience exists
	found := false
	for _, candidate := range audience {
		for _, aud := range token.Claims.Audiences.Aud {
			seen = append(seen, aud)
			found = found || candidate == aud
		}
	}
	if !found {
		err = &InvalidFormat{fmt.Sprintf("no expected audience | expected %s | seen %s", audience, seen)}
		return
	}

	// Though optional in the JWT spec we always require a Key ID to be present
	// to resist various known attacks.
	// if len(token.Header.Kid) == 0 {
	// 	err = ErrInvalidKid
	// 	return
	// }
	if len(token.Header.Kid) > 0 {
		var key VerificationKey
		key, err = verifier.store.Get(token.Claims.Issuer, token.Header.Kid)
		if key == nil {
			err = ErrUnknownKey
			return
		}

		// Ensure algorithms match!
		if key.Algorithm() != token.Header.Alg {
			err = ErrInvalidAlgorithm
			return
		}

		if !key.Verify(jose.KeyOpsVerify, []byte(signed), token.Signature) {
			err = ErrInvalidSignature
			return
		}
		kid = key.Kid()
	}

	claims = &token.Claims
	return
}

// NewJwtVerifier creates a JWT Verifier for a given truststore
func NewJwtVerifier(ks TrustStore) *JwtVerifierImpl {
	return &JwtVerifierImpl{store: ks}
}
