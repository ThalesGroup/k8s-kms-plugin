/*
 * // Copyright 2020 Thales DIS CPL Inc
 * //
 * // Permission is hereby granted, free of charge, to any person obtaining
 * // a copy of this software and associated documentation files (the
 * // "Software"), to deal in the Software without restriction, including
 * // without limitation the rights to use, copy, modify, merge, publish,
 * // distribute, sublicense, and/or sell copies of the Software, and to
 * // permit persons to whom the Software is furnished to do so, subject to
 * // the following conditions:
 * //
 * // The above copyright notice and this permission notice shall be
 * // included in all copies or substantial portions of the Software.
 * //
 * // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * // EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * // NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * // LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * // OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * // WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package keystore

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"

	// #nosec G505 (see use below)
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Converts a key object (of some kind) to a pem.Block
//
// Currently only RSA and ECDSA private keys are supported.
//
// Returns nil if the input is not a (known) private key type.
//
// Terminates the process if a marshaling error occurs (for instance,
// an ECC key using an unrecognized curve).
func pemBlockForKey(priv interface{}) *pem.Block {
	// TODO doesn't seem to be used.
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2) // TODO
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// Returns the public key corresponding to a private key.
//
// Panics if the input is not a (known) private key type.
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *dsa.PrivateKey:
		return &k.PublicKey
	default:
		panic(fmt.Sprintf("unrecognized private key type %T", priv))
	}
}

// Structure of SubjectPublicKeyInfo (RFC5280 4.1)
//
// See createSKI().
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// Create an RFC5280-friendly KeyIdentifier for a public key
//
// Currently only RSA public keys are supported.
func createSKI(key crypto.PublicKey) ([]byte, error) {
	switch v := key.(type) {
	case *rsa.PublicKey:
		// This seems to be SHA1(subjectPublicKey) as mandated
		// by RFC5280 4.2.1.2.
		//
		// TODO I've not validated this against any kind of
		// test vector.
		encodedPub, err := x509.MarshalPKIXPublicKey(v)
		if err != nil {
			return nil, err
		}
		var subPKI subjectPublicKeyInfo
		if _, err = asn1.Unmarshal(encodedPub, &subPKI); err != nil {
			return nil, err
		}
		// #nosec G401 we sign the public key not the hash anyway
		hash := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
		return hash[:], nil
	default:
		return nil, fmt.Errorf("Unsupported key type %T", key)
	}
}

// Return a fingerprint for a certificate
//
// Note that this reflects the value of the whole certificate, not
// (for instance) the public key it contains.
func fingerprintCert(cert *x509.Certificate) string {
	digester := sha256.New()
	if _, err := digester.Write(cert.Raw); err != nil {
		log.Panicf("%s", err)
	}
	fp := digester.Sum(nil)
	return fmt.Sprintf("%x", fp)
}

// Exclusive upper bound for serial numbers
//
// RFC5280 4.1.2.2 requires:
// - no more than 160 bits
// - serial numbers from a given CA must be unique
//
// We'll get into trouble around 2^80 certificates.
var serialBound = (&big.Int{}).Exp(big.NewInt(2), big.NewInt(160), nil)

// Return a random serial number suitable for an RFC5280 certificate
func newSerial(randReader io.Reader) (serial *big.Int, err error) {
	if serial, err = rand.Int(randReader, serialBound); err != nil {
		log.Errorf("creating serial: %s", err)
		return
	}
	return
}

// Serialize a certificate chain
//
// The result is suitable for adding to a gose.Jwk representation of a key.
func encodeCertificates(certs []*x509.Certificate) (certStrings []string) {
	certStrings = make([]string, len(certs))
	for i, cert := range certs {
		certStrings[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return
}

// Test whether a filename is safe
func safeName(name string) bool {
	if len(name) == 0 || name[0] == '.' || strings.ContainsAny(name, "/") {
		return false
	}
	if strings.ToLower(name) == intKekName {
		return false
	}
	return true
}

// Return true if subject is empty
func emptySubject(subject *pkix.Name) bool {
	return len(subject.ToRDNSequence()) == 0
}

// Return true if two OIDs are equal
func oidEqual(a, b []int) bool {
	return reflect.DeepEqual(a, b)
}
