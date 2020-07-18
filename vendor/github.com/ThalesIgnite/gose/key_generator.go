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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/ThalesIgnite/gose/jose"
)

const minimumRsaKeySize = 2048 // The minimum RSA key size allowable as defined https://tools.ietf.org/html/rfc7518#section-3.5
var (
	rsaSigningAlgs = map[jose.Alg]bool{
		jose.AlgRS256: true,
		jose.AlgRS384: true,
		jose.AlgRS512: true,
		jose.AlgPS256: true,
		jose.AlgPS384: true,
		jose.AlgPS512: true,
	}
	ecdsAlgs = map[jose.Alg]elliptic.Curve{
		jose.AlgES256: elliptic.P256(),
		jose.AlgES384: elliptic.P384(),
		jose.AlgES512: elliptic.P521(),
	}
	authenticatedEncryptionAlgs = map[jose.Alg]int{
		jose.AlgA128GCM: 16,
		jose.AlgA192GCM: 24,
		jose.AlgA256GCM: 32,
	}
	rsaEncryptionAlgs = map[jose.Alg]bool{
		jose.AlgRSAOAEP: true,
	}
)

func generateRsaKey(alg jose.Alg, bitLen int, operations []jose.KeyOps) (jose.Jwk, *rsa.PrivateKey, error) {
	if bitLen < minimumRsaKeySize {
		return nil, nil, ErrInvalidKeySize
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bitLen)
	if err != nil {
		return nil, nil, err
	}
	jwk, err := JwkFromPrivateKey(privateKey, operations, []*x509.Certificate{})
	if err != nil {
		return nil, nil, err
	}
	jwk.SetAlg(alg)
	return jwk, privateKey, nil
}

//RsaSigningKeyGenerator handles generating a RSA signing key
type RsaSigningKeyGenerator struct {
}

//Generate an RSA key using a given algorithm, length, and scope to certain jwk operations.
func (generator *RsaSigningKeyGenerator) Generate(alg jose.Alg, bitLen int, operations []jose.KeyOps) (SigningKey, error) {
	/* Generate an RSA signing jwk. */
	if _, ok := rsaSigningAlgs[alg]; !ok {
		return nil, ErrInvalidAlgorithm
	}
	jwk, _, err := generateRsaKey(alg, bitLen, operations)
	if err != nil {
		return nil, err
	}
	return NewSigningKey(jwk, operations)
}

//ECDSASigningKeyGenerator handles generating an ECDSA signing key
type ECDSASigningKeyGenerator struct {
}

//Generate an ECDSA key using a given algorithm, and scoped to certain jwk operations.
func (g *ECDSASigningKeyGenerator) Generate(alg jose.Alg, operations []jose.KeyOps) (SigningKey, error) {

	curve, ok := ecdsAlgs[alg]
	if !ok {
		return nil, ErrInvalidAlgorithm
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	jwk, err := JwkFromPrivateKey(privateKey, operations, []*x509.Certificate{})
	if err != nil {
		return nil, err
	}
	jwk.SetAlg(alg)

	return NewSigningKey(jwk, operations)
}

// AuthenticatedEncryptionKeyGenerator can be used to create AuthenticatedEncryptionKeys.
type AuthenticatedEncryptionKeyGenerator struct{}

// Generate generate a Generate and JWK representation.
func (g *AuthenticatedEncryptionKeyGenerator) Generate(alg jose.Alg, operations []jose.KeyOps) (AuthenticatedEncryptionKey, jose.Jwk, error) {
	sz, ok := authenticatedEncryptionAlgs[alg]
	if !ok {
		return nil, nil, ErrInvalidAlgorithm
	}

	key := make([]byte, sz)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	jwk, err := JwkFromSymmetric(key, alg)
	if err != nil {
		return nil, nil, err
	}
	jwk.SetOps(operations)
	cryptor, err := NewAesGcmCryptorFromJwk(jwk, operations)
	if err != nil {
		return nil, nil, err
	}
	return cryptor, jwk, nil
}

//RsaKeyDecryptionKeyGenerator handles generating a RSA encryption keys
type RsaKeyDecryptionKeyGenerator struct {
}

//Generate an RSA key using a given algorithm, length, and scope to certain jwk operations.
func (generator *RsaKeyDecryptionKeyGenerator) Generate(alg jose.Alg, bitLen int, operations []jose.KeyOps) (AsymmetricDecryptionKey, error) {
	/* Generate an RSA encryption jwk. */
	if _, ok := rsaEncryptionAlgs[alg]; !ok {
		return nil, ErrInvalidAlgorithm
	}
	jwk, key, err := generateRsaKey(alg, bitLen, operations)
	if err != nil {
		return nil, err
	}
	return &RsaPrivateKeyImpl{
		jwk: jwk,
		key: key,
	}, nil
}
