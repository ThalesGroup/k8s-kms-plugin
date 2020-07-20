// Copyright 2019 Thales eSecurity
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package estclient

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"reflect"

	"github.com/fullsailor/pkcs7"
	"github.com/pkg/errors"
)

// algs contains mappings between signature algorithms and the appropriate
// public key algorithm and hashes
var algs = map[x509.SignatureAlgorithm]algAndHash{
	x509.SHA256WithRSA:    {x509.RSA, crypto.SHA256},
	x509.SHA384WithRSA:    {x509.RSA, crypto.SHA384},
	x509.SHA512WithRSA:    {x509.RSA, crypto.SHA512},
	x509.DSAWithSHA256:    {x509.DSA, crypto.SHA256},
	x509.ECDSAWithSHA256:  {x509.ECDSA, crypto.SHA256},
	x509.ECDSAWithSHA384:  {x509.ECDSA, crypto.SHA384},
	x509.ECDSAWithSHA512:  {x509.ECDSA, crypto.SHA512},
	x509.SHA256WithRSAPSS: {x509.RSA, crypto.SHA256},
	x509.SHA384WithRSAPSS: {x509.RSA, crypto.SHA384},
	x509.SHA512WithRSAPSS: {x509.RSA, crypto.SHA512},
}

type algAndHash struct {
	alg  x509.PublicKeyAlgorithm
	hash crypto.Hash
}

// readCertificate reads a single certificate from a base64-encoded PKCS #7 structure. It
// will return an error if there is more than one certificate contained.
func readCertificate(p7data string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(p7data)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode base64 message")
	}

	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse pkcs7")
	}

	if len(p7.Certificates) != 1 {
		return nil, errors.Errorf("expected 1 certificate, found %d", len(p7.Certificates))
	}

	return p7.Certificates[0], nil
}

type dsaSignature struct {
	R, S *big.Int
}

// parseCaCerts picks through the response from /cacerts and tries to identify the EST TA certificate
// as well as the special OldWithOld, OldWithNew and NewWithOld certificates, if present. Finally, any
// certificates that don't match the previous four categories are assumed to be chain certificates and
// are returned as such.
func parseCaCerts(p7data string) (*CaCertsInfo, error) {
	der, err := base64.StdEncoding.DecodeString(p7data)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode base64 message")
	}

	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse pkcs7")
	}

	// First we identify self-signed certs. There can be at most two: the EstTA certificate is
	// required, and optionally there may be an OldWithOld certificate. If two are present,
	// EstTA will have the latest NotAfter date (per RFC 7030 4.1.3).
	result := &CaCertsInfo{}

	certs := p7.Certificates
	var otherCerts []*x509.Certificate

	for _, c := range certs {
		selfSigned, err := isSelfSigned(c)
		if err != nil {
			return nil, err
		}

		if selfSigned {
			if result.EstTA != nil {
				if result.OldWithOld != nil {
					return nil, errors.New("too many self-signed certificates found in response")
				}

				// compare timestamps
				if c.NotAfter.After(result.EstTA.NotAfter) {
					result.OldWithOld = result.EstTA
					result.EstTA = c
				} else {
					result.OldWithOld = c
				}
			} else {
				result.EstTA = c
			}
		} else {
			otherCerts = append(otherCerts, c)
		}
	}

	// It would be an error not to have the EstTA cert, by this point
	if result.EstTA == nil {
		return nil, errors.New("failed to find EST TA certificate in bag")
	}

	// We don't bother to look for OldWithNew and NewWithOld if we don't already have OldWithOld
	if result.OldWithOld != nil {
		for _, c := range otherCerts {

			hasNewPublicKey, err := pubKeysEqual(result.EstTA.PublicKey, c.PublicKey)
			if err != nil {
				return nil, err
			}

			hasOldPublicKey, err := pubKeysEqual(result.OldWithOld.PublicKey, c.PublicKey)
			if err != nil {
				return nil, err
			}

			if hasNewPublicKey {
				// should be a NewWithOld cert
				signedByOld, err := isSignedBy(c, result.OldWithOld.PublicKey)
				if err != nil {
					return nil, err
				}
				if signedByOld {
					if !bytes.Equal(c.RawIssuer, result.OldWithOld.RawSubject) {
						// Ignoring potential NewWithOld certificate because the issuer does not match the OldWithOld subject
						continue
					}

					if result.NewWithOld != nil {
						return nil, errors.New("found multiple NewWithOld certificates")
					}
					result.NewWithOld = c
				} else {
					return nil, errors.New("failed to interpret certificates")
				}

			} else if hasOldPublicKey {
				// should be an OldWithNew cert
				signedByNew, err := isSignedBy(c, result.EstTA.PublicKey)
				if err != nil {
					return nil, err
				}
				if signedByNew {

					if !bytes.Equal(c.RawIssuer, result.EstTA.RawSubject) {
						// Ignoring potential OldWithNew certificate because the issuer does not match the EST TA subject
						continue
					}

					if result.OldWithNew != nil {
						return nil, errors.New("found multiple OldWithNew certificates")
					}
					result.OldWithNew = c
				} else {
					return nil, errors.New("failed to interpret certificates")
				}
			} else {
				// Not a special certificate, so add to the unordered chain of other certs
				result.EstChainCerts = append(result.EstChainCerts, c)
			}

		}
	}

	return result, nil
}

// pubKeysEqual compares two public keys for equality
func pubKeysEqual(pk1 interface{}, pk2 interface{}) (bool, error) {
	switch k1 := pk1.(type) {
	case *rsa.PublicKey:
		if k2, ok := pk2.(*rsa.PublicKey); ok {
			return k1.N.Cmp(k2.N) == 0 && k1.E == k2.E, nil
		}
		return false, nil

	case *dsa.PublicKey:
		if k2, ok := pk2.(*dsa.PublicKey); ok {
			return k1.G.Cmp(k2.G) == 0 && k1.P.Cmp(k2.P) == 0 && k1.Q.Cmp(k2.Q) == 0 && k1.Y.Cmp(k2.Y) == 0, nil
		}
		return false, nil

	case *ecdsa.PublicKey:
		if k2, ok := pk2.(*ecdsa.PublicKey); ok {
			return k1.Y.Cmp(k2.Y) == 0 && k1.X.Cmp(k2.X) == 0 && reflect.TypeOf(k1.Curve) == reflect.TypeOf(k2.Curve), nil
		}
		return false, nil

	default:
		return false, errors.New("unknown algorithm type")
	}
}

// isSelfSigned checks the certificate has an identical issuer and subject and that the public
// key contained in the certificate matches the private key used to sign the certificate.
func isSelfSigned(c *x509.Certificate) (bool, error) {
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false, nil
	}

	return isSignedBy(c, c.PublicKey)
}

func isSignedBy(c *x509.Certificate, pubKey interface{}) (bool, error) {
	alg, found := algs[c.SignatureAlgorithm]
	if !found {
		return false, errors.Errorf("unsupported signature algorithm: %s", c.SignatureAlgorithm.String())
	}

	hash := alg.hash
	h := hash.New()
	h.Write(c.RawTBSCertificate)
	hashedCert := h.Sum(nil)

	switch pk := pubKey.(type) {
	case *rsa.PublicKey:
		if algs[c.SignatureAlgorithm].alg != x509.RSA {
			return false, nil
		}

		switch c.SignatureAlgorithm {
		case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			return rsa.VerifyPSS(pk, hash, hashedCert, c.Signature, nil) == nil, nil
		default:
			return rsa.VerifyPKCS1v15(pk, hash, hashedCert, c.Signature) == nil, nil
		}
	case *dsa.PublicKey:
		if algs[c.SignatureAlgorithm].alg != x509.DSA {
			return false, nil
		}

		dsaSig := new(dsaSignature)
		if remain, err := asn1.Unmarshal(c.Signature, dsaSig); err != nil {
			return false, err
		} else if len(remain) > 0 {
			return false, errors.New("failed to parse DSA signature, additional data found")
		}

		return dsa.Verify(pk, hashedCert, dsaSig.R, dsaSig.S), nil

	case *ecdsa.PublicKey:
		if algs[c.SignatureAlgorithm].alg != x509.ECDSA {
			return false, nil
		}

		dsaSig := new(dsaSignature)
		if remain, err := asn1.Unmarshal(c.Signature, dsaSig); err != nil {
			return false, err
		} else if len(remain) > 0 {
			return false, errors.New("failed to parse ECDSA signature, additional data found")
		}

		return ecdsa.Verify(pk, hashedCert, dsaSig.R, dsaSig.S), nil

	default:
		return false, errors.New("unknown or unsupported public key algorithm")
	}
}

// validateAuthData checks for valid combinations of authentication data.
func validateAuthData(authData AuthData) error {
	if (authData.ID == nil && authData.Secret != nil) || (authData.ID != nil && authData.Secret == nil) {
		return errors.New("invalid authentication data: specify both ID and Secret")
	}
	if (authData.Key == nil && authData.ClientCert != nil) || (authData.Key != nil && authData.ClientCert == nil) {
		return errors.New("invalid authentication data: specify both Key and ClientCert")
	}
	return nil
}
