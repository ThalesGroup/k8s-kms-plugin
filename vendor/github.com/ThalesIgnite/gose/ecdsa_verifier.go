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
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/ThalesIgnite/gose/jose"
	"github.com/sirupsen/logrus"
)

// ECVerificationKeyImpl implements the ECDSA Verification Logic
type ECVerificationKeyImpl struct {
	key   ecdsa.PublicKey
	jwk jose.Jwk
}

const ecPublicKeyPemType = "EC PUBLIC KEY"

// Algorithm return algorithm
func (verifier *ECVerificationKeyImpl) Algorithm() jose.Alg {
	return verifier.jwk.Alg()
}

// Verify signed data matches signature and jwk
// The input signature is encoded as r || s which is different to the standard go crypto interface specification.
// The serialization format is chosen instead to match that defined in the JSON Web Signature spec
// https://tools.ietf.org/html/rfc7515#appendix-A.3.1.
func (verifier *ECVerificationKeyImpl) Verify(operation jose.KeyOps, data []byte, signature []byte) bool {
	ops := intersection(validVerificationOps, verifier.jwk.Ops())
	if !isSubset(ops, []jose.KeyOps{operation}) {
		return false
	}

	// Get the key
	ecdsaKey := verifier.key
	opts := algToOptsMap[verifier.Algorithm()].(*ECDSAOptions)
	keySize := opts.keySizeBytes
	if len(signature) != 2*keySize {
		return false
	}

	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])

	// Create hasher
	if !opts.Hash.Available() {
		return false
	}
	hasher := opts.HashFunc().New()
	if _, err := hasher.Write([]byte(data)); err != nil {
		logrus.Panicf("%s", err)
	}

	// Verify the signature
	return ecdsa.Verify(&ecdsaKey, hasher.Sum(nil), r, s)
}

// Certificates returns the certs for this key
func (verifier *ECVerificationKeyImpl) Certificates() []*x509.Certificate {
	return verifier.jwk.X5C()
}

// Jwk returns the key as a jose.JWK type, or error
func (verifier *ECVerificationKeyImpl) Jwk() (jose.Jwk, error) {
	return verifier.jwk, nil
}

// Marshal marshals the key into a compact JWK string, or error
func (verifier *ECVerificationKeyImpl) Marshal() (string, error) {
	return JwkToString(verifier.jwk)
}

// MarshalPem marshals the key as a PEM formatted string, or error
func (verifier *ECVerificationKeyImpl) MarshalPem() (string, error) {
	derEncoded, err := x509.MarshalPKIXPublicKey(&verifier.key)
	if err != nil {
		return "", err
	}

	block := pem.Block{
		Type:  ecPublicKeyPemType,
		Bytes: derEncoded,
	}
	output := bytes.Buffer{}
	if err := pem.Encode(&output, &block); err != nil {
		return "", err
	}
	return string(output.Bytes()), nil
}

//Kid returns the key's id
func (verifier *ECVerificationKeyImpl) Kid() string {
	return verifier.jwk.Kid()
}
