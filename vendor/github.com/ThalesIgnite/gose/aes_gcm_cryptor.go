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
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/ThalesIgnite/gose/jose"
)

var validEncryptionOpts = []jose.KeyOps{jose.KeyOpsEncrypt}
var validDecryptionOpts = []jose.KeyOps{jose.KeyOpsDecrypt}
var validCryptorOpts = []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}

// AesGcmCryptor provides AES GCM encryption and decryption functions.
type AesGcmCryptor struct {
	kid  string
	alg  jose.Alg
	aead cipher.AEAD
	opts []jose.KeyOps
	rng  io.Reader
}

// Kid the key identity
func (cryptor *AesGcmCryptor) Kid() string {
	return cryptor.kid
}

// Algorithm the supported algorithm
func (cryptor *AesGcmCryptor) Algorithm() jose.Alg {
	return cryptor.alg
}

// GenerateNonce generate a nonce of the correct size for use with GCM encryption/decryption from a random source.
func (cryptor *AesGcmCryptor) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, cryptor.aead.NonceSize())
	if _, err := cryptor.rng.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// Open decrypt a previously encrypted ciphertext.
func (cryptor *AesGcmCryptor) Open(operation jose.KeyOps, nonce, ciphertext, aad, tag []byte) (plaintext []byte, err error) {
	ops := intersection(validDecryptionOpts, cryptor.opts)
	if !isSubset(ops, []jose.KeyOps{operation}) {
		err = ErrInvalidOperations
		return
	}
	dst := make([]byte, 0, len(ciphertext))
	ciphertextAndTag := make([]byte, len(ciphertext)+len(tag))
	_ = copy(ciphertextAndTag, ciphertext)
	_ = copy(ciphertextAndTag[len(ciphertext):], tag)
	if dst, err = cryptor.aead.Open(dst, nonce, ciphertextAndTag, aad); err != nil {
		return
	}
	plaintext = dst
	return
}

// Seal encrypt a supplied plaintext and AAD.
func (cryptor *AesGcmCryptor) Seal(operation jose.KeyOps, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	ops := intersection(validEncryptionOpts, cryptor.opts)
	if !isSubset(ops, []jose.KeyOps{operation}) {
		err = ErrInvalidOperations
		return
	}
	if len(nonce) != cryptor.aead.NonceSize() {
		err = ErrInvalidNonce
		return
	}
	sz := cryptor.aead.Overhead() + len(plaintext)
	dst := make([]byte, 0, sz)
	dst = cryptor.aead.Seal(dst, nonce, plaintext, aad)
	ciphertext = dst[:len(plaintext)]
	tag = dst[len(plaintext):]
	return
}

// NewAesGcmCryptorFromJwk create a new instance of an AesGCmCryptor from a JWK.
func NewAesGcmCryptorFromJwk(jwk jose.Jwk, required []jose.KeyOps) (AuthenticatedEncryptionKey, error) {
	/* Check jwk can be used to encrypt or decrypt */
	ops := intersection(validCryptorOpts, jwk.Ops())
	if len(ops) == 0 {
		return nil, ErrInvalidOperations
	}
	/* Load the jwk */
	aead, err := LoadSymmetricAEAD(jwk, required)
	if err != nil {
		return nil, err
	}
	return &AesGcmCryptor{
		kid:  jwk.Kid(),
		alg:  jwk.Alg(),
		aead: aead,
		rng:  rand.Reader,
		opts: jwk.Ops(),
	}, nil
}

// NewAesGcmCryptor create a new instance of an AesGCmCryptor from the supplied parameters.
func NewAesGcmCryptor(aead cipher.AEAD, rng io.Reader, kid string, alg jose.Alg, opeartions []jose.KeyOps) (AuthenticatedEncryptionKey, error) {
	return &AesGcmCryptor{
		kid:  kid,
		alg:  alg,
		aead: aead,
		rng:  rng,
		opts: opeartions,
	}, nil
}
