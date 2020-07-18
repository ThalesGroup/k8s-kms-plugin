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
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/ThalesIgnite/gose/jose"
)

//InvalidFormat is an interface for handling invalid format errors
type InvalidFormat struct {
	what string
}

func (err *InvalidFormat) Error() string {
	return fmt.Sprintf("Invalid format: %s", err.what)
}

// Algorithmed is an interface that exposes which algorithm a type can be used
// with.
type Algorithmed interface {
	Algorithm() jose.Alg
}

// Key is an interface representing a cryptographic key.
type Key interface {
	// Kid returns the identity of the key.
	Kid() string
}

// MarshalableKey is an interface representing a key that can be marshaled into a JWK.
type MarshalableKey interface {
	// Jwk returns the Key as a JSON Web Key.
	Jwk() (jose.Jwk, error)
	// Marshal marshals a key to it's compact JWK string representation.
	Marshal() (string, error)
}

// CertifiableKey is an interface representing a key that can have an associated certificate and PEM representation.
type CertifiableKey interface {
	// MarshalPem marshals a key to it's PEM representation.
	MarshalPem() (string, error)
	// Certificates returns the certificate chain for the given key.
	Certificates() []*x509.Certificate
}

// SigningKey interface implementers both digest and signing of data.
type SigningKey interface {
	Key
	MarshalableKey
	CertifiableKey
	Algorithmed
	// Key returns the underlying key used to sign
	Key() crypto.Signer
	// Sign digest and sign the given data.
	Sign(jose.KeyOps, []byte) ([]byte, error)
	// Verifier get the matching verification key.
	Verifier() (VerificationKey, error)
}

// VerificationKey implements verification of a cryptographic signature.
type VerificationKey interface {
	Key
	MarshalableKey
	CertifiableKey
	Algorithmed
	// Verify verifies the operation being performed is supported and
	// that the signature is derived from the data.
	Verify(operation jose.KeyOps, data []byte, signature []byte) bool
}

// AsymmetricEncryptionKey implements encryption using an asymmetric key.
type AsymmetricEncryptionKey interface {
	Key
	MarshalableKey
	CertifiableKey
	Algorithmed
	Encrypt(jose.KeyOps, []byte) ([]byte, error)
}

// AsymmetricDecryptionKey provides asymmetric decryption (private key) capabilities.
type AsymmetricDecryptionKey interface {
	Key
	Algorithmed
	Decrypt(jose.KeyOps, []byte) ([]byte, error)
	// Encryptor get the matching encryption key.
	Encryptor() (AsymmetricEncryptionKey, error)
}

// AuthenticatedEncryptionKey implements authenticated encryption and decryption.
type AuthenticatedEncryptionKey interface {
	Key
	Algorithmed
	// GenerateNonce generates a nonce of the correct size for use in Sealinging operations.
	GenerateNonce() ([]byte, error)
	// Seal the given plaintext returning ciphertext and authentication tag.
	Seal(operation jose.KeyOps, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)
	// Open and validate the given ciphertext and tag returning the plaintext.
	Open(operation jose.KeyOps, nonce, ciphertext, aad, tag []byte) (plaintext []byte, err error)
}

// JwtSigner implements generation of signed compact JWTs as defined by https://tools.ietf.org/html/rfc7519.
type JwtSigner interface {
	// Issuer returns the identity of the issuing authority
	Issuer() string
	// Sign signs a set of claims returning a serialized JWT.
	Sign(claims *jose.SettableJwtClaims, untyped map[string]interface{}) (string, error)
}

// JwtVerifier implements verification of signed compact JWTs as defined by https://tools.ietf.org/html/rfc7519.
type JwtVerifier interface {
	// Verify verifies a JWT is a valid jwt where the caller can specify a number of allowable audiences.
	Verify(jwt string, audience []string) (kid string, claims *jose.JwtClaims, err error)
}

// TrustStore provides the ability to manage trusted root public keys for use when verifying cryptographic
// signatures.
type TrustStore interface {
	Add(issuer string, jwk jose.Jwk) error
	Remove(issuer, kid string) bool
	Get(issuer, kid string) (vk VerificationKey, err error)
}

// AsymmetricDecryptionKeyStore provides the ability to access asymmetric decryption keys.
type AsymmetricDecryptionKeyStore interface {
	Get(kid string) (k AsymmetricDecryptionKey, err error)
}

// JweEncryptor implements encryption of arbitary plaintext into a compact JWE as defined by https://tools.ietf.org/html/rfc7516.
type JweEncryptor interface {
	Encrypt(plaintext, aad []byte) (string, error)
}

// JweDecryptor implements decryption and verification of a given ciphertext and aad to a plaintext as defined by https://tools.ietf.org/html/rfc7516.
type JweDecryptor interface {
	Decrypt(jwe string) (plaintext, aad []byte, err error)
}
