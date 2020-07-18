package gose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/ThalesIgnite/gose/jose"
)

// JweRsaKeyEncryptionEncryptorImpl implements RSA Key Encryption CEK mode.
type JweRsaKeyEncryptionEncryptorImpl struct {
	recipientJwk jose.Jwk
	recipientKey *rsa.PublicKey
	cekAlg jose.Alg
}

// Encrypt encrypts the given plaintext into a compact JWE. Optional authenticated data can be included which is appended
// to the JWE protected header.
func (e *JweRsaKeyEncryptionEncryptorImpl) Encrypt(plaintext, aad []byte) (string, error) {
	keyGenerator := &AuthenticatedEncryptionKeyGenerator{}
	cek, jwk, err := keyGenerator.Generate(e.cekAlg, []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt})
	if err != nil {
		return "", err
	}
	cekJwk := jwk.(*jose.OctSecretKey)

	nonce, err := cek.GenerateNonce()
	if err != nil {
		return "", err
	}

	var blob *jose.Blob
	var customHeaderFields jose.JweCustomHeaderFields
	if len(aad) > 0 {
		blob = &jose.Blob{B: aad}
		customHeaderFields = jose.JweCustomHeaderFields{
			OtherAad: blob,
		}
	}

	encryptedKey, err := rsa.EncryptOAEP(crypto.SHA1.New(), rand.Reader, e.recipientKey, cekJwk.K.Bytes(), nil)
	if err != nil {
		return "", err
	}

	jwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgRSAOAEP,
				Kid: e.recipientJwk.Kid(),
			},
			Enc:                   algToEncMap[cekJwk.Alg()],
			JweCustomHeaderFields: customHeaderFields,
		},
		EncryptedKey: encryptedKey,
		Iv:           nonce,
		Plaintext:    plaintext,
	}
	if err = jwe.MarshalHeader(); err != nil {
		return "", err
	}

	if jwe.Ciphertext, jwe.Tag, err = cek.Seal(jose.KeyOpsEncrypt, jwe.Iv, jwe.Plaintext, jwe.MarshalledHeader); err != nil {
		return "", err
	}
	return jwe.Marshal(), nil
}

// NewJweRsaKeyEncryptionEncryptorImpl returns an instance of JweRsaKeyEncryptionEncryptorImpl configured with the given
// JWK.
func NewJweRsaKeyEncryptionEncryptorImpl(recipient jose.Jwk, contentEncryptionAlg jose.Alg) (*JweRsaKeyEncryptionEncryptorImpl, error) {
	if _, ok := authenticatedEncryptionAlgs[contentEncryptionAlg]; !ok {
		return nil, ErrInvalidAlgorithm
	}
	if !isSubset(recipient.Ops(), []jose.KeyOps{jose.KeyOpsEncrypt})  {
		return nil, ErrInvalidOperations
	}
	kek, err := LoadPublicKey(recipient, validEncryptionOpts)
	if err != nil {
		return nil, err
	}
	rsaKek, ok := kek.(*rsa.PublicKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	return &JweRsaKeyEncryptionEncryptorImpl{
		recipientKey: rsaKek,
		recipientJwk: recipient,
		cekAlg: contentEncryptionAlg,
	}, nil
}
