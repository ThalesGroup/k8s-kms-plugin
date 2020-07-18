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

package jose

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
)

//Certificate leaf for JWK
type Certificate struct {
	Certificate *x509.Certificate
}

//MarshalJSON as byte slice or error
func (c *Certificate) MarshalJSON() (dst []byte, err error) {
	dst, err = marshalJSONBlob(c.Certificate.Raw, base64.StdEncoding)
	return
}

//UnmarshalJSON byte slice to certificate, or error
func (c *Certificate) UnmarshalJSON(src []byte) (err error) {
	var b []byte
	if b, err = unmarshalJSONBlob(src, base64.StdEncoding); err != nil {
		return
	}
	c.Certificate, err = x509.ParseCertificate(b)
	return err
}

//Fingerprint represents a SHA1 digest
type Fingerprint struct {
	digest []byte
}

//Bytes of blob in byte slice
func (f *Fingerprint) Bytes() []byte {
	return f.digest
}

//SetBytes of Fingerprint
func (f *Fingerprint) SetBytes(val []byte) *Fingerprint {
	f.digest = val
	return f
}

//UnmarshalJSON byte slice to Fingerprint, or error
func (f *Fingerprint) UnmarshalJSON(src []byte) error {
	var err error
	if f.digest, err = unmarshalJSONBlob(src, base64.RawURLEncoding); err != nil {
		return err
	}
	if len(f.digest) != 20 {
		return ErrJwkInvalidFingerprintfomat
	}
	return nil
}

//MarshalJSON Fingerprint to byte slice
func (f *Fingerprint) MarshalJSON() (dst []byte, err error) {
	if len(f.digest) != 20 {
		err = ErrJwkInvalidFingerprintfomat
		return
	}
	dst, err = marshalJSONBlob(f.digest, base64.RawURLEncoding)
	return
}

// Jwk provides an interface for setting and getting common fields
// irrespective of key type.
type Jwk interface {
	Kty() Kty
	Use() KeyUse
	SetUse(use KeyUse)
	Ops() []KeyOps
	SetOps(ops []KeyOps)
	Alg() Alg
	SetAlg(alg Alg)
	Kid() string
	SetKid(kid string)
	X5C() []*x509.Certificate
	SetX5C(x5c []*x509.Certificate)
	X5T() *Fingerprint
	SetX5T(hash *Fingerprint)
	// TODO: Add x5t#S256 handling including consistency checking
	// CheckConsistency verify the JWK is well formed.
	CheckConsistency() error
}

// Common Jwk fields
type jwkFields struct {
	KeyUse KeyUse        `json:"use,omitempty"`
	KeyOps []KeyOps      `json:"key_ops,omitempty"`
	KeyAlg Alg           `json:"alg,omitempty"`
	KeyKid string        `json:"kid,omitempty"`
	KeyX5C []Certificate `json:"x5c,omitempty"`
	KeyX5T *Fingerprint  `json:"x5t,omitempty"`
}

func (j *jwkFields) Use() KeyUse {
	return j.KeyUse
}

func (j *jwkFields) SetUse(use KeyUse) {
	j.KeyUse = use
}

func (j *jwkFields) Ops() []KeyOps {
	return j.KeyOps
}

func (j *jwkFields) SetOps(ops []KeyOps) {
	j.KeyOps = ops
}

func (j *jwkFields) Alg() Alg {
	return j.KeyAlg
}

func (j *jwkFields) SetAlg(alg Alg) {
	j.KeyAlg = alg
}

func (j *jwkFields) Kid() string {
	return j.KeyKid
}

func (j *jwkFields) SetKid(kid string) {
	j.KeyKid = kid
}

func (j *jwkFields) X5C() []*x509.Certificate {
	certs := make([]*x509.Certificate, 0, len(j.KeyX5C))
	for _, c := range j.KeyX5C {
		certs = append(certs, c.Certificate)
	}
	return certs
}

func (j *jwkFields) SetX5C(x5c []*x509.Certificate) {
	for _, c := range x5c {
		j.KeyX5C = append(j.KeyX5C, Certificate{
			Certificate: c,
		})
	}
}

func (j *jwkFields) X5T() *Fingerprint {
	return j.KeyX5T
}

func (j *jwkFields) SetX5T(blob *Fingerprint) {
	j.KeyX5T = blob
}

func (j *jwkFields) CheckConsistency() error {
	// Check for duplicate KeyOps.
	if len(j.KeyOps) > 0 {
		for i, candidate := range j.KeyOps[:len(j.KeyOps)-1] {
			for _, item := range j.KeyOps[i+1:] {
				if candidate == item {
					return ErrDuplicateKeyOps
				}
			}
		}
	}
	// Check certificate and thumb-print matches

	if len(j.KeyX5C) > 0 {
		if j.KeyX5T != nil {
			digester := crypto.SHA1.New()
			if _, err := digester.Write(j.KeyX5C[0].Certificate.Raw); err != nil {
				return err
			}
			digest := digester.Sum(nil)
			if subtle.ConstantTimeCompare(digest, j.KeyX5T.digest) != 1 {
				return ErrJwkInconsistentCertificateFields
			}
		}
	}
	return nil
}

//PublicRsaKeyFields Public RSA specific fields.
type PublicRsaKeyFields struct {
	N BigNum `json:"n"`
	E BigNum `json:"e"`
}

//PublicRsaKey Public RSA JWK type.
type PublicRsaKey struct {
	jwkFields
	PublicRsaKeyFields
}

//Kty key type
func (k *PublicRsaKey) Kty() Kty {
	return KtyRSA
}

//MarshalJSON to byte slice or error
func (k *PublicRsaKey) MarshalJSON() (dst []byte, err error) {
	toMarshal := struct {
		*jwkFields
		*PublicRsaKeyFields
		Kty Kty `json:"kty"`
	}{
		jwkFields:          &k.jwkFields,
		PublicRsaKeyFields: &k.PublicRsaKeyFields,
		Kty:                KtyRSA,
	}
	dst, err = json.Marshal(&toMarshal)
	return
}

//UnmarshalJSON byte slice or error
func (k *PublicRsaKey) UnmarshalJSON(src []byte) (err error) {
	toUnmarshal := struct {
		*jwkFields
		*PublicRsaKeyFields
		Kty Kty `json:"kty"`
	}{
		jwkFields:          &k.jwkFields,
		PublicRsaKeyFields: &k.PublicRsaKeyFields,
		Kty:                "",
	}
	if err = json.Unmarshal(src, &toUnmarshal); err != nil {
		return
	}
	if toUnmarshal.Kty != KtyRSA {
		err = ErrUnexpectedKeyType
	}
	err = k.CheckConsistency()
	return
}

//PrivateRsaKeyFields Private RSA specific fields.
type PrivateRsaKeyFields struct {
	D  BigNum `json:"d"`
	P  BigNum `json:"p"`
	Q  BigNum `json:"q"`
	Dp BigNum `json:"dp"`
	Dq BigNum `json:"dq"`
	Qi BigNum `json:"qi"`
}

//PrivateRsaKey Private RSA JWK type.
type PrivateRsaKey struct {
	PublicRsaKey
	PrivateRsaKeyFields
}

//Kty key type
func (k *PrivateRsaKey) Kty() Kty {
	return KtyRSA
}

//MarshalJSON to byte slice or error
func (k *PrivateRsaKey) MarshalJSON() (dst []byte, err error) {
	toMarshal := struct {
		Kty Kty `json:"kty"`
		*jwkFields
		*PublicRsaKeyFields
		*PrivateRsaKeyFields
	}{
		Kty:                 KtyRSA,
		jwkFields:           &k.jwkFields,
		PublicRsaKeyFields:  &k.PublicRsaKeyFields,
		PrivateRsaKeyFields: &k.PrivateRsaKeyFields,
	}
	dst, err = json.Marshal(&toMarshal)
	return
}

//UnmarshalJSON byte slice or error
func (k *PrivateRsaKey) UnmarshalJSON(src []byte) (err error) {
	toUnmarshal := struct {
		Kty Kty `json:"kty"`
		*jwkFields
		*PublicRsaKeyFields
		*PrivateRsaKeyFields
	}{
		Kty:                 "",
		jwkFields:           &k.jwkFields,
		PublicRsaKeyFields:  &k.PublicRsaKeyFields,
		PrivateRsaKeyFields: &k.PrivateRsaKeyFields,
	}
	if err = json.Unmarshal(src, &toUnmarshal); err != nil {
		return
	}
	if toUnmarshal.Kty != KtyRSA {
		err = ErrUnexpectedKeyType
	}
	err = k.CheckConsistency()
	return
}

//PublicEcKeyFields Public EC specific fields.
type PublicEcKeyFields struct {
	Crv Crv    `json:"crv"`
	X   BigNum `json:"x"`
	Y   BigNum `json:"y"`
}

//PublicEcKey Public EC JWK type.
type PublicEcKey struct {
	jwkFields
	PublicEcKeyFields
}

//Kty key type
func (k *PublicEcKey) Kty() Kty {
	return KtyEC
}

//MarshalJSON to byte slice or error
func (k *PublicEcKey) MarshalJSON() (dst []byte, err error) {
	toMarshal := struct {
		*jwkFields
		*PublicEcKeyFields
		Kty Kty `json:"kty"`
	}{
		jwkFields:         &k.jwkFields,
		PublicEcKeyFields: &k.PublicEcKeyFields,
		Kty:               KtyEC,
	}
	dst, err = json.Marshal(&toMarshal)
	return
}

//UnmarshalJSON byte slice or error
func (k *PublicEcKey) UnmarshalJSON(src []byte) (err error) {
	toUnmarshal := struct {
		Kty Kty `json:"kty"`
		*jwkFields
		*PublicEcKeyFields
	}{
		Kty:               "",
		jwkFields:         &k.jwkFields,
		PublicEcKeyFields: &k.PublicEcKeyFields,
	}
	if err = json.Unmarshal(src, &toUnmarshal); err != nil {
		return
	}
	if toUnmarshal.Kty != KtyEC {
		err = ErrUnexpectedKeyType
	}
	err = k.CheckConsistency()
	return
}

//PrivateEcKeyFields Private EC specific fields.
type PrivateEcKeyFields struct {
	D BigNum `json:"d"`
}

//PrivateEcKey Private EC JWK type.
type PrivateEcKey struct {
	PublicEcKey
	PrivateEcKeyFields
}

//Kty key type
func (k *PrivateEcKey) Kty() Kty {
	return KtyEC
}

//MarshalJSON to byte slice or error
func (k *PrivateEcKey) MarshalJSON() (dst []byte, err error) {
	toMarshal := struct {
		Kty Kty `json:"kty"`
		*jwkFields
		*PublicEcKeyFields
		*PrivateEcKeyFields
	}{
		Kty:                KtyEC,
		jwkFields:          &k.jwkFields,
		PublicEcKeyFields:  &k.PublicEcKeyFields,
		PrivateEcKeyFields: &k.PrivateEcKeyFields,
	}
	dst, err = json.Marshal(&toMarshal)
	return
}

//UnmarshalJSON byte slice or error
func (k *PrivateEcKey) UnmarshalJSON(src []byte) (err error) {
	toUnmarshal := struct {
		Kty Kty `json:"kty"`
		*jwkFields
		*PublicEcKeyFields
		*PrivateEcKeyFields
	}{
		Kty:                "",
		jwkFields:          &k.PublicEcKey.jwkFields,
		PublicEcKeyFields:  &k.PublicEcKeyFields,
		PrivateEcKeyFields: &k.PrivateEcKeyFields,
	}
	if err = json.Unmarshal(src, &toUnmarshal); err != nil {
		return
	}
	if toUnmarshal.Kty != KtyEC {
		err = ErrUnexpectedKeyType
	}
	err = k.CheckConsistency()
	return
}

//OctSecretKeyFields Secret key specific fields.
type OctSecretKeyFields struct {
	K Blob `json:"k"`
}

//OctSecretKey Secret key JWK type.
type OctSecretKey struct {
	jwkFields
	OctSecretKeyFields
}

//Kty key type
func (k *OctSecretKey) Kty() Kty {
	return KtyOct
}

//MarshalJSON to byte slice or error
func (k *OctSecretKey) MarshalJSON() (dst []byte, err error) {
	toMarshal := struct {
		*jwkFields
		*OctSecretKeyFields
		Kty Kty `json:"kty"`
	}{
		jwkFields:          &k.jwkFields,
		OctSecretKeyFields: &k.OctSecretKeyFields,
		Kty:                KtyOct,
	}
	dst, err = json.Marshal(&toMarshal)
	return
}

//UnmarshalJSON to to byte slice or error
func (k *OctSecretKey) UnmarshalJSON(src []byte) (err error) {
	toUnmarshal := struct {
		*jwkFields
		*OctSecretKeyFields
		Kty Kty `json:"kty"`
	}{
		jwkFields:          &k.jwkFields,
		OctSecretKeyFields: &k.OctSecretKeyFields,
		Kty:                "",
	}
	if err = json.Unmarshal(src, &toUnmarshal); err != nil {
		return
	}
	if toUnmarshal.Kty != KtyOct {
		err = ErrUnexpectedKeyType
	}
	err = k.CheckConsistency()
	return
}

//UnmarshalJwk serialization into a concrete type.
func UnmarshalJwk(reader io.ReadSeeker) (jwk Jwk, err error) {
	// First unmarshal Kty so that we can work out how to proceed.
	decoder := json.NewDecoder(reader)
	keyType := struct {
		Kty Kty `json:"kty"`
	}{}
	if err = decoder.Decode(&keyType); err != nil {
		return
	}
	if _, err = reader.Seek(0, io.SeekStart); err != nil {
		return
	}
	switch keyType.Kty {
	case KtyRSA:
		var rsa PrivateRsaKey
		if err = decoder.Decode(&rsa); err != nil {
			return
		}
		// Look at D to assert whether this is a private or public RSA key.
		if rsa.D.Int().BitLen() == 0 {
			jwk = &rsa.PublicRsaKey
		} else {
			jwk = &rsa
		}
		return
	case KtyEC:
		var ec PrivateEcKey
		if err = decoder.Decode(&ec); err != nil {
			return
		}
		if ec.D.Int().BitLen() == 0 {
			jwk = &ec.PublicEcKey
		} else {
			jwk = &ec
		}
		return
	case KtyOct:
		var oct OctSecretKey
		if err = decoder.Decode(&oct); err != nil {
			return
		}
		jwk = &oct
	default:
		err = ErrUnsupportedKeyType
		return
	}
	return
}
