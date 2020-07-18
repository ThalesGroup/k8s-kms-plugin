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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strings"

	"crypto/ecdsa"
	"encoding/json"
	"log"

	"github.com/ThalesIgnite/gose/jose"
)

const (
	//Version1 of the JOSE
	version1 = "v1"
)

func fromBase64(b64 string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	var result big.Int
	result.SetBytes(b)
	return &result, nil
}

func isSubset(set []jose.KeyOps, subset []jose.KeyOps) bool {
	if len(subset) == 0 {
		return false
	}
	result := true
	for _, req := range subset {
		opExists := false
		for _, op := range set {
			opExists = opExists || (req == op)
		}
		result = result && opExists
	}
	return result
}

func intersection(first []jose.KeyOps, second []jose.KeyOps) []jose.KeyOps {
	var result []jose.KeyOps
	for _, a := range first {
		for _, b := range second {
			if a == b {
				result = append(result, a)
			}
		}
	}
	return result
}

//LoadPrivateKey loads the jwk into a crypto.Signer for performing signing operations
func LoadPrivateKey(jwk jose.Jwk, required []jose.KeyOps) (crypto.Signer, error) {
	privateKeyAlgs := map[jose.Alg]bool{
		jose.AlgRS256: true,
		jose.AlgRS384: true,
		jose.AlgRS512: true,
		jose.AlgPS256: true,
		jose.AlgPS384: true,
		jose.AlgPS512: true,
		jose.AlgES256: true,
		jose.AlgES384: true,
		jose.AlgES512: true,
		jose.AlgRSAOAEP: true,
	}

	if _, ok := privateKeyAlgs[jwk.Alg()]; !ok {
		return nil, ErrInvalidKeyType
	}
	if required != nil && len(required) > 0 && !isSubset(jwk.Ops(), required) {
		return nil, ErrInvalidOperations
	}
	switch v := jwk.(type) {
	case *jose.PrivateRsaKey:
		/* Import RSA private key. */
		if v.D.Empty() || v.E.Empty() || v.N.Empty() {
			/* This is a public RSA jwk. */
			return nil, ErrInvalidKeyType
		}
		var key rsa.PrivateKey

		/* Ensure positive 32-bit integer. */
		if v.E.Int().BitLen() > 32 || v.E.Int().Sign() < 1 {
			return nil, ErrInvalidExponent
		}

		key.Primes = []*big.Int{v.P.Int(), v.Q.Int()}
		key.D = v.D.Int()
		key.E = int(v.E.Int().Int64())
		key.N = v.N.Int()
		key.Precompute()
		// Check the consistency of the precomputable values contained in the JWK.
		if key.Precomputed.Dp.Cmp(v.Dp.Int()) != 0 || key.Precomputed.Dq.Cmp(v.Dq.Int()) != 0 || key.Precomputed.Qinv.Cmp(v.Qi.Int()) != 0 {
			return nil, ErrInconsistentKeyValues
		}
		return &key, nil
	case *jose.PrivateEcKey:
		if v.D.Empty() {
			/* This is a public jwk. */
			return nil, ErrInvalidKeyType
		}
		var key ecdsa.PrivateKey

		key.X = v.X.Int()
		key.Y = v.Y.Int()
		key.D = v.D.Int()
		key.Curve = algToOptsMap[v.Alg()].(*ECDSAOptions).curve
		return &key, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

//LoadPublicKey loads jwk as a public key for cryptographic verification operations.
func LoadPublicKey(jwk jose.Jwk, required []jose.KeyOps) (crypto.PublicKey, error) {
	publicKeyAlgs := map[jose.Alg]bool{
		jose.AlgRS256: true,
		jose.AlgRS384: true,
		jose.AlgRS512: true,
		jose.AlgPS256: true,
		jose.AlgPS384: true,
		jose.AlgPS512: true,
		jose.AlgES256: true,
		jose.AlgES384: true,
		jose.AlgES512: true,
		jose.AlgRSAOAEP: true,
	}
	if _, ok := publicKeyAlgs[jwk.Alg()]; !ok {
		return nil, ErrInvalidKeyType
	}
	if required != nil && len(required) > 0 && !isSubset(jwk.Ops(), required) {
		return nil, ErrInvalidOperations
	}
	switch v := jwk.(type) {
	case *jose.PublicRsaKey:
		/* Import RSA private jwk. */
		if v.N.Empty() || v.E.Empty() {
			/* There's no public parameters. */
			return nil, ErrInvalidKeyType
		}
		var key rsa.PublicKey
		/* Ensure positive 32-bit integer. */
		if v.E.Int().BitLen() > 32 || v.E.Int().Sign() < 1 {
			return nil, ErrInvalidExponent
		}
		key.E = int(v.E.Int().Int64())
		key.N = v.N.Int()
		return &key, nil
	case *jose.PublicEcKey:
		var key ecdsa.PublicKey
		if v.X.Empty() || v.Y.Empty() {
			/* There's no public parameters. */
			return nil, ErrInvalidKeyType
		}
		key.X = v.X.Int()
		key.Y = v.Y.Int()
		key.Curve = algToOptsMap[v.Alg()].(*ECDSAOptions).curve
		return &key, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

//LoadJws loads signature, or errors
func LoadJws(jws string) (protectedHeader *jose.JwsHeader, header []byte, data []byte, payload []byte, signature []byte, err error) {
	var tmp jose.JwsHeader
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, nil, nil, nil, nil, ErrInvalidJwsCompactEncoding
	}
	header, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, nil, nil, ErrInvalidJwsBase64HeaderEncoding
	}
	if err := json.Unmarshal(header, &tmp); err != nil {
		return nil, nil, nil, nil, nil, ErrInvalidJwsHeaderEncoding
	}
	protectedHeader = &tmp
	data, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, nil, nil, ErrInvalidJwsBase64BodyEncoding
	}
	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, nil, nil, ErrInvalidJwsBase64SignatureEncoding
	}
	payload = []byte(fmt.Sprintf("%s.%s", parts[0], parts[1]))
	return
}

//CalculateKeyID deterministically calculates the ID for the given jwk
func CalculateKeyID(jwk jose.Jwk) (string, error) {
	/* Deterministic calculation of a jwk's identity. */
	switch typed := jwk.(type) {
	case *jose.PublicRsaKey:
		encoded := strings.Join([]string{
			version1,
			"jwk",
			string(jwk.Kty()),
			base64.RawURLEncoding.EncodeToString(typed.N.Int().Bytes()),
			base64.RawURLEncoding.EncodeToString(typed.E.Int().Bytes()),
		}, ".")
		digester := sha256.New()
		if _, err := digester.Write([]byte(encoded)); err != nil {
			log.Panicf("%s", err)
		}
		digest := digester.Sum(nil)
		return fmt.Sprintf("%x", digest), nil
	case *jose.PublicEcKey:
		encoded := strings.Join([]string{
			version1,
			"jwk",
			string(jwk.Kty()),
			base64.RawURLEncoding.EncodeToString(typed.X.Int().Bytes()),
			base64.RawURLEncoding.EncodeToString(typed.Y.Int().Bytes()),
		}, ".")
		digester := sha256.New()
		if _, err := digester.Write([]byte(encoded)); err != nil {
			log.Panicf("%s", err)
		}
		digest := digester.Sum(nil)
		return fmt.Sprintf("%x", digest), nil
	case *jose.OctSecretKey:
		// Should we include alg in symmetric jwk
		// identification? The spec is RFC7517 s4.5 and does
		// not give a clear steer. I've adopted the answer
		// 'no' for now but we might want to revisit this.
		digester := sha256.New()
		encoded := strings.Join([]string{
			version1,
			"jwk",
			string(jwk.Kty()),
			base64.RawURLEncoding.EncodeToString(typed.K.Bytes()),
		}, ".")
		digester.Write([]byte(encoded))
		digest := digester.Sum(nil)
		return fmt.Sprintf("%x", digest), nil
	default:
		return "", ErrUnsupportedKeyType
	}
}

//LoadJwk load io.ReadSeeker as a JWK or error
func LoadJwk(reader io.ReadSeeker, required []jose.KeyOps) (jwk jose.Jwk, err error) {
	if jwk, err = jose.UnmarshalJwk(reader); err != nil {
		return
	}
	if len(required) > 0 && !isSubset(jwk.Ops(), required) {
		return
	}
	return
}

//LoadJwkFromFile loads file as JWK or error
func LoadJwkFromFile(file string, required []jose.KeyOps) (jose.Jwk, error) {
	/* Load jwk from file. */
	fd, err := os.Open(file)
	if err != nil {
		return nil, ErrInvalidSigningKeyURL
	}
	defer fd.Close()
	return LoadJwk(fd, required)
}

var inverseOps = map[jose.KeyOps]jose.KeyOps{
	jose.KeyOpsEncrypt: jose.KeyOpsDecrypt,
	jose.KeyOpsDecrypt: jose.KeyOpsEncrypt,
	jose.KeyOpsSign:    jose.KeyOpsVerify,
	jose.KeyOpsVerify:  jose.KeyOpsSign,
}

func rsaBitsToAlg(bitLen int) jose.Alg {
	/* Based on NIST recommendations from 2016. */
	if bitLen >= 15360 {
		return jose.AlgPS512
	} else if bitLen >= 7680 {
		return jose.AlgPS384
	}
	return jose.AlgPS256
}

func ecBitsToAlg(bitLen int) jose.Alg {
	switch bitLen {
	case 256:
		return jose.AlgES256
	case 384:
		return jose.AlgES384
	case 521:
		return jose.AlgES512
	default:
		return "Unsupported"
	}
}

//PublicFromPrivate extracts public jwk from private jwk in JWK format
func PublicFromPrivate(in jose.Jwk) (jose.Jwk, error) {
	var out jose.Jwk
	switch k := in.(type) {
	case *jose.PrivateRsaKey:
		if k.D.Empty() || k.Q.Empty() || k.Dq.Empty() || k.P.Empty() ||
			k.Dp.Empty() || k.Qi.Empty() || k.N.Empty() || k.E.Empty() {
			/* This is either badly formed or a public jwk. */
			return nil, ErrInvalidKeyType
		}
		var result jose.PublicRsaKey
		result.PublicRsaKeyFields = k.PublicRsaKeyFields
		out = &result
	case *jose.PrivateEcKey:
		var result jose.PublicEcKey
		result.PublicEcKeyFields = k.PublicEcKeyFields
		out = &result
	default:
		return nil, ErrUnsupportedKeyType
	}
	out.SetKid(in.Kid())
	out.SetAlg(in.Alg())
	var ops []jose.KeyOps
	for _, op := range in.Ops() {
		ops = append(ops, inverseOps[op])
	}
	out.SetOps(ops)
	out.SetX5C(in.X5C())
	return out, nil
}

//JwkToString return JWK as string
func JwkToString(jwk jose.Jwk) (string, error) {
	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func base64EncodeInt32(val uint32) string {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, &val); err != nil {
		log.Panicf("%s", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

//JwkFromPrivateKey builds JWK, from a crypto.Signer, with certificates, and scoped to certain operations,  or errors
func JwkFromPrivateKey(privateKey crypto.Signer, operations []jose.KeyOps, certs []*x509.Certificate) (jose.Jwk, error) {
	var jwk jose.Jwk
	switch v := privateKey.(type) {
	case *rsa.PrivateKey:
		if v.E > math.MaxInt32 {
			return nil, ErrInvalidExponent
		}
		alg := rsaBitsToAlg(v.N.BitLen())
		/* Key generation. */
		v.Precompute()
		var rsa jose.PrivateRsaKey
		rsa.SetAlg(alg)
		rsa.Q.Set(v.Primes[1])
		rsa.Qi.Set(v.Precomputed.Qinv)
		rsa.Dq.Set(v.Precomputed.Dq)
		rsa.P.Set(v.Primes[0])
		rsa.Dp.Set(v.Precomputed.Dp)
		rsa.N.Set(v.N)
		rsa.E.Set(big.NewInt(int64(v.E)))
		rsa.D.Set(v.D)
		jwk = &rsa
	case *ecdsa.PrivateKey:
		var ec jose.PrivateEcKey
		alg := ecBitsToAlg(v.Curve.Params().BitSize)
		ec.SetAlg(alg)
		ec.X.Set(v.X)
		ec.Y.Set(v.Y)
		ec.D.Set(v.D)
		ec.Crv = jose.Crv(v.Curve.Params().Name)
		jwk = &ec
	default:
		return nil, ErrUnsupportedKeyType
	}
	jwk.SetOps(operations)
	if len(certs) > 0 {
		jwk.SetX5C(certs)
	}
	publicKey, err := PublicFromPrivate(jwk)
	if err != nil {
		// We should have erred before we ever get here.
		log.Panic("Failed to derive public jwk from private")
	}
	kid, err := CalculateKeyID(publicKey)
	if err != nil {
		// We should have erred before we ever get here.
		log.Panic("Failed to calculate Key ID")
	}
	jwk.SetKid(kid)

	return jwk, nil
}

//JwkFromPublicKey builds public JWK, from a crypto.Signer, with certificates, and scoped to certain operations,  or errors
func JwkFromPublicKey(publicKey crypto.PublicKey, operations []jose.KeyOps, certs []*x509.Certificate) (jose.Jwk, error) {
	var jwk jose.Jwk
	switch v := publicKey.(type) {
	case *rsa.PublicKey:
		if v.E > math.MaxInt32 {
			return nil, ErrInvalidExponent
		}
		alg := rsaBitsToAlg(v.N.BitLen())
		/* Key generation. */
		var rsa jose.PublicRsaKey
		rsa.SetAlg(alg)
		rsa.N.Set(v.N)
		rsa.E.Set(big.NewInt(int64(v.E)))
		jwk = &rsa
	case *ecdsa.PublicKey:
		var ec jose.PublicEcKey
		alg := ecBitsToAlg(v.Curve.Params().BitSize)
		ec.SetAlg(alg)
		ec.X.Set(v.X)
		ec.Y.Set(v.Y)
		ec.Crv = jose.Crv(v.Curve.Params().Name)
		jwk = &ec
	default:
		return nil, ErrUnsupportedKeyType
	}
	jwk.SetOps(operations)
	kid, _ := CalculateKeyID(jwk)
	jwk.SetKid(kid)
	if len(certs) > 0 {
		jwk.SetX5C(certs)
	}
	return jwk, nil
}

// Characteristics of symmetric algorithms
type symmetricAlgInfo struct {
	minLen          int
	maxLen          int
	confidentiality bool
	integrity       bool
}

// Table of known symmetric algorithms
var symmetricAlgs = map[jose.Alg]symmetricAlgInfo{
	jose.AlgA128GCM: {16, 16, true, true},
	jose.AlgA192GCM: {24, 24, true, true},
	jose.AlgA256GCM: {32, 32, true, true},
}

// JwkFromSymmetric converts a byte string to a jose.Jwk, given a particular JWK algorithm.
func JwkFromSymmetric(key []byte, alg jose.Alg) (jwk *jose.OctSecretKey, err error) {
	// Validity checking & default ops
	ops := make([]jose.KeyOps, 0, 4)
	if sai, ok := symmetricAlgs[alg]; ok {
		if len(key) < sai.minLen || len(key) > sai.maxLen {
			err = ErrInvalidKeyLength
			return
		}
		if sai.confidentiality {
			ops = append(ops, jose.KeyOpsEncrypt, jose.KeyOpsDecrypt)
		}
		if sai.integrity {
			ops = append(ops, jose.KeyOpsSign, jose.KeyOpsVerify)
		}
	} else {
		err = ErrUnsupportedKeyType
		return
	}
	oct := jose.OctSecretKey{}
	oct.SetOps(ops)
	oct.SetAlg(alg)
	oct.K.SetBytes(key)
	var kid string
	if kid, err = CalculateKeyID(&oct); err != nil {
		return
	}
	oct.SetKid(kid)
	jwk = &oct
	return
}

// Extract the raw bytes of a symmetric jwk. Only 'oct' keys are supported.
func loadSymmetricBytes(jwk jose.Jwk, required []jose.KeyOps) (key []byte, err error) {
	// TODO I made this private to discourage promiscuous use of
	// raw key bytes, but if required it could easily be public.
	if _, ok := symmetricAlgs[jwk.Alg()]; !ok {
		err = ErrInvalidKeyType
		return
	}
	if required != nil && len(required) > 0 && !isSubset(jwk.Ops(), required) {
		err = ErrInvalidOperations
		return
	}
	switch v := jwk.(type) {
	case *jose.OctSecretKey:
		key = v.K.Bytes()
		return
	default:
		err = ErrUnsupportedKeyType
		return
	}
}

// LoadSymmetricAEAD returns a cipher.AEAD for a jwk.
func LoadSymmetricAEAD(jwk jose.Jwk, required []jose.KeyOps) (a cipher.AEAD, err error) {
	var key []byte
	if key, err = loadSymmetricBytes(jwk, required); err != nil {
		return
	}
	v := jwk.(*jose.OctSecretKey) // can't fail, previous call would have errored
	switch v.Alg() {
	case jose.AlgA128GCM, jose.AlgA192GCM, jose.AlgA256GCM:
		var b cipher.Block
		if b, err = aes.NewCipher(key); err != nil {
			return
		}
		if a, err = cipher.NewGCM(b); err != nil {
			return
		}
		return
	default:
		err = ErrUnsupportedKeyType
		return
	}
}

// JwtToString returns the full string of the Jwt or error
func JwtToString(jwt jose.Jwt) (full string, err error) {

	return
}
