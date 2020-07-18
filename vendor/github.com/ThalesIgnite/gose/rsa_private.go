package gose

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/sirupsen/logrus"
)

// RsaPrivateKeyImpl provides software based signing and decryption capabilities for use during JWT and JWE processing.
type RsaPrivateKeyImpl struct {
	jwk   jose.Jwk
	key   *rsa.PrivateKey
}

// Key returns the underlying crypto.Signer implementation.
func (rsaKey *RsaPrivateKeyImpl) Key() crypto.Signer {
	return rsaKey.key
}

//Operations returns the allowed operations for the SigningKey
func (rsaKey *RsaPrivateKeyImpl) Operations() []jose.KeyOps {
	return rsaKey.jwk.Ops()
}

//Kid returns the jwk id
func (rsaKey *RsaPrivateKeyImpl) Kid() string {
	/* JIT jwk load. */
	return rsaKey.jwk.Kid()
}

//Jwk returns the JWK
func (rsaKey *RsaPrivateKeyImpl) Jwk() (jose.Jwk, error) {
	return rsaKey.jwk, nil
}

//Algorithm returns the Algorithm
func (rsaKey *RsaPrivateKeyImpl) Algorithm() jose.Alg {
	return rsaKey.jwk.Alg()
}

//Marshal marshal the key to a JWK string, or error
func (rsaKey *RsaPrivateKeyImpl) Marshal() (string, error) {
	return JwkToString(rsaKey.jwk)
}

//MarshalPem marshal the key to a PEM string, or error
func (rsaKey *RsaPrivateKeyImpl) MarshalPem() (string, error) {
	var pemType string
	var derEncoded []byte
	pemType = rsaPrivateKeyPemType
	derEncoded = x509.MarshalPKCS1PrivateKey(rsaKey.key)
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
func (rsaKey *RsaPrivateKeyImpl) Sign(requested jose.KeyOps, data []byte) ([]byte, error) {
	/* Verify the operation being requested is supported by the jwk. */
	ops := intersection(validSignerOps, rsaKey.jwk.Ops())
	if !isSubset(ops, []jose.KeyOps{requested}) {
		return nil, ErrInvalidOperations
	}
	/* Calculate digest. */
	digester := algToOptsMap[rsaKey.jwk.Alg()].HashFunc().New()
	if _, err := digester.Write(data); err != nil {
		logrus.Panicf("%s", err)
	}
	digest := digester.Sum(nil)
	opts := algToOptsMap[rsaKey.jwk.Alg()]
	return rsaKey.key.Sign(rand.Reader, digest, opts)
}

//Certificates of signing key
func (rsaKey *RsaPrivateKeyImpl) Certificates() []*x509.Certificate {
	return rsaKey.jwk.X5C()
}

// Decrypt decrypt the given ciphertext returning the derived plaintext.
func (rsaKey *RsaPrivateKeyImpl) Decrypt(requested jose.KeyOps, ciphertext []byte) ([]byte, error) {
	ops := intersection(validDecryptionOps, rsaKey.jwk.Ops())
	if !isSubset(ops, []jose.KeyOps{requested}) {
		return nil, ErrInvalidOperations
	}
	// SHA1 is still safe when used in the construction of OAEP.
	return rsa.DecryptOAEP(crypto.SHA1.New(), rand.Reader, rsaKey.key, ciphertext, nil)
}

func (rsaKey *RsaPrivateKeyImpl) publicKey() (*RsaPublicKeyImpl, error) {
	publicJwk, err := PublicFromPrivate(rsaKey.jwk)
	if err != nil {
		return nil, err
	}
	return &RsaPublicKeyImpl{
		key: rsaKey.key.PublicKey,
		jwk: publicJwk,
	}, nil
}

//Verifier verification key for signing jwk
func (rsaKey *RsaPrivateKeyImpl) Verifier() (VerificationKey, error) {
	return rsaKey.publicKey()
}

//Encryptor get encryption key
func (rsaKey *RsaPrivateKeyImpl) Encryptor() (AsymmetricEncryptionKey, error) {
	return rsaKey.publicKey()
}

// NewRsaDecryptionKey returns a new instance of RsaPrivateKeyImpl configured using he given JWK.
func NewRsaDecryptionKey(jwk jose.Jwk) (*RsaPrivateKeyImpl, error) {
	signer, err := LoadPrivateKey(jwk, []jose.KeyOps{jose.KeyOpsDecrypt})
	if err != nil {
		return nil, err
	}
	rsaKey, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	return &RsaPrivateKeyImpl{
		jwk: jwk,
		key: rsaKey,
	}, nil
}

