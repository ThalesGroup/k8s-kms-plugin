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

//RsaPublicKeyImpl implements RSA verification and encryption APIs
type RsaPublicKeyImpl struct {
	key rsa.PublicKey
	jwk jose.Jwk
}

const rsaPublicKeyPemType = "RSA PUBLIC KEY"

var (
	pssAlgs = map[jose.Alg]bool{
		jose.AlgPS256: true,
		jose.AlgPS384: true,
		jose.AlgPS512: true,
	}
)

//Kid returns the key's id
func (k *RsaPublicKeyImpl) Kid() string {
	return k.jwk.Kid()
}

//Algorithm returns algorithm
func (k *RsaPublicKeyImpl) Algorithm() jose.Alg {
	return k.jwk.Alg()
}

//Jwk returns the public JWK
func (k *RsaPublicKeyImpl) Jwk() (jose.Jwk, error) {
	jwk, err := JwkFromPublicKey(&k.key, k.jwk.Ops(), k.jwk.X5C())
	if err != nil {
		return nil, err
	}
	jwk.SetAlg(k.jwk.Alg())
	return jwk, nil
}

//Marshal returns the key marshalled to a JWK string, or error
func (k *RsaPublicKeyImpl) Marshal() (string, error) {
	jwk, err := k.Jwk()
	if err != nil {
		return "", err
	}
	return JwkToString(jwk)
}

//MarshalPem returns the key marshalled to a PEM string, or error
func (k *RsaPublicKeyImpl) MarshalPem() (string, error) {
	derEncoded, err := x509.MarshalPKIXPublicKey(&k.key)
	if err != nil {
		return "", err
	}

	block := pem.Block{
		Type:  rsaPublicKeyPemType,
		Bytes: derEncoded,
	}
	output := bytes.Buffer{}
	if err := pem.Encode(&output, &block); err != nil {
		return "", err
	}
	return string(output.Bytes()), nil
}

//Verify data matches signature
func (k *RsaPublicKeyImpl) Verify(operation jose.KeyOps, data []byte, signature []byte) bool {
	ops := intersection(validVerificationOps, k.jwk.Ops())
	if !isSubset(ops, []jose.KeyOps{operation}) {
		return false
	}
	digester := algToOptsMap[k.jwk.Alg()].HashFunc().New()
	if _, err := digester.Write(data); err != nil {
		logrus.Panicf("%s", err)
	}
	digest := digester.Sum(nil)
	var err error
	if _, ok := pssAlgs[k.jwk.Alg()]; ok {
		err = rsa.VerifyPSS(&k.key, algToOptsMap[k.jwk.Alg()].HashFunc(), digest, signature, algToOptsMap[k.jwk.Alg()].(*rsa.PSSOptions))
	} else {
		err = rsa.VerifyPKCS1v15(&k.key, algToOptsMap[k.jwk.Alg()].HashFunc(), digest, signature)
	}
	return err == nil
}

// Encrypt encrypts the given plaintext returning the derived ciphertext.
func (k *RsaPublicKeyImpl) Encrypt(requested jose.KeyOps, data []byte) ([]byte, error) {
	/* Verify the operation being requested is supported by the jwk. */
	ops := intersection(validEncryptionOps, k.jwk.Ops())
	if !isSubset(ops, []jose.KeyOps{requested}) {
		return nil, ErrInvalidOperations
	}
	// SHA1 is still safe when used in the construction of OAEP.
	return rsa.EncryptOAEP(crypto.SHA1.New(), rand.Reader, &k.key, data, nil)
}

//Certificates for verification key
func (k *RsaPublicKeyImpl) Certificates() []*x509.Certificate {
	return k.jwk.X5C()
}

// NewRsaPublicKeyImpl create a new RsaPublicKeyImpl instance.
func NewRsaPublicKeyImpl(jwk jose.Jwk) (*RsaPublicKeyImpl, error) {
	publicKey, err := LoadPublicKey(jwk, nil)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := publicKey.(rsa.PublicKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	return &RsaPublicKeyImpl{
		key: rsaKey,
		jwk: jwk,
	}, err
}