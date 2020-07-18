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
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/ThalesIgnite/gose/jose"
	"github.com/sirupsen/logrus"
)

//SigningKeyImpl implements a RSA signing key
type SigningKeyImpl struct {
	jwk   jose.Jwk
	key   crypto.Signer
	certs []*x509.Certificate
}

/* Alg to digest map. */
var algToOptsMap = map[jose.Alg]crypto.SignerOpts{
	jose.AlgPS256: &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256},
	jose.AlgPS384: &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384},
	jose.AlgPS512: &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512},
	jose.AlgRS256: crypto.SHA256,
	jose.AlgRS384: crypto.SHA384,
	jose.AlgRS512: crypto.SHA512,
	jose.AlgES256: &ECDSAOptions{Hash: crypto.SHA256, keySizeBytes: 32, curveBits: 256, curve: elliptic.P256()},
	jose.AlgES384: &ECDSAOptions{Hash: crypto.SHA384, keySizeBytes: 48, curveBits: 384, curve: elliptic.P384()},
	jose.AlgES512: &ECDSAOptions{Hash: crypto.SHA512, keySizeBytes: 66, curveBits: 521, curve: elliptic.P521()},
}

var validSignerOps = []jose.KeyOps{
	jose.KeyOpsSign,
}

var validEncryptionOps = []jose.KeyOps{
	jose.KeyOpsEncrypt,
}

var validDecryptionOps = []jose.KeyOps{
	jose.KeyOpsDecrypt,
}

const rsaPrivateKeyPemType = "RSA PRIVATE KEY"

//NewSigningKey returns a SignignKey for a jose.JWK with required jwk operations
func NewSigningKey(jwk jose.Jwk, required []jose.KeyOps) (SigningKey, error) {
	/* Check jwk can be used to sign */
	ops := intersection(validSignerOps, jwk.Ops())
	if len(ops) == 0 {
		return nil, ErrInvalidOperations
	}
	/* Load the jwk */
	k, err := LoadPrivateKey(jwk, required)
	if err != nil {
		return nil, err
	}

	switch jwk.(type) {
	case *jose.PrivateRsaKey:
		return &SigningKeyImpl{jwk: jwk, key: k, certs: jwk.X5C()}, nil
	case *jose.PrivateEcKey:
		return &ECDSASigningKey{jwk: jwk, key: k, certs: jwk.X5C()}, nil
	default:
		return nil, ErrInvalidKeyType
	}
}

//Key returns the crypto.Signer
func (signer *SigningKeyImpl) Key() crypto.Signer {
	return signer.key
}

//Operations returns the allowed operations for the SigningKey
func (signer *SigningKeyImpl) Operations() []jose.KeyOps {
	return signer.jwk.Ops()
}

//Kid returns the jwk id
func (signer *SigningKeyImpl) Kid() string {
	/* JIT jwk load. */
	return signer.jwk.Kid()
}

//Jwk returns the JWK
func (signer *SigningKeyImpl) Jwk() (jose.Jwk, error) {
	return signer.jwk, nil
}

//Algorithm returns the Algorithm
func (signer *SigningKeyImpl) Algorithm() jose.Alg {
	return signer.jwk.Alg()
}

//Marshal marshal the key to a JWK string, or error
func (signer *SigningKeyImpl) Marshal() (string, error) {
	return JwkToString(signer.jwk)
}

//MarshalPem marshal the key to a PEM string, or error
func (signer *SigningKeyImpl) MarshalPem() (string, error) {
	var pemType string
	var derEncoded []byte
	switch k := signer.key.(type) {
	case *rsa.PrivateKey:
		pemType = rsaPrivateKeyPemType
		derEncoded = x509.MarshalPKCS1PrivateKey(k)
	default:
		return "", ErrUnsupportedKeyType
	}
	block := pem.Block{
		Type:  pemType,
		Bytes: derEncoded,
	}
	output := bytes.Buffer{}
	if err := pem.Encode(&output, &block); err != nil {
		return "", err
	}
	return string(output.Bytes()), nil
}

//Sign perform signing operations on data, or error
func (signer *SigningKeyImpl) Sign(requested jose.KeyOps, data []byte) ([]byte, error) {
	/* Verify the operation being requested is supported by the jwk. */
	ops := intersection(validSignerOps, signer.jwk.Ops())
	if !isSubset(ops, []jose.KeyOps{requested}) {
		return nil, ErrInvalidOperations
	}
	/* Calculate digest. */
	digester := algToOptsMap[signer.jwk.Alg()].HashFunc().New()
	if _, err := digester.Write(data); err != nil {
		logrus.Panicf("%s", err)
	}
	digest := digester.Sum(nil)
	opts := algToOptsMap[signer.jwk.Alg()]
	return signer.key.Sign(rand.Reader, digest, opts)
}

//Certificates of signing key
func (signer *SigningKeyImpl) Certificates() []*x509.Certificate {
	return signer.certs
}

//Verifier verification key for signing jwk
func (signer *SigningKeyImpl) Verifier() (VerificationKey, error) {
	publicJwk, err := PublicFromPrivate(signer.jwk)
	if err != nil {
		return nil, err
	}
	return NewVerificationKey(publicJwk)
}
