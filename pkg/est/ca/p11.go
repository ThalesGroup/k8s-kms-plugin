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

package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/go-openapi/runtime/middleware"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/operations/operation"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// P11 CA for RFC7030 based enrollment/registration of services/machines/devices
type P11 struct {
	ca        string
	key       string
	cert      string
	ctxt11    *crypto11.Context
	config    *crypto11.Config
	ServerTLS *tls.Config
	ClientTLS *tls.Config
}

const (
	errorBase64       = "Invalid base64 in request."
	errorBadCertReq   = "Failed to read certificate request. Expected DER-encoded PKCS#10 data."
	errorCertIssuance = "An error occured when requesting the certificate."
	errorEncodingCert = "An error occured when encoding the certificate."
)

func NewP11EST(ca, key, cert string, config *crypto11.Config) (e *P11, err error) {

	e = &P11{
		ca:     ca,
		key:    key,
		cert:   cert,
		config: config,
	}
	if e.ctxt11, err = crypto11.Configure(e.config); err != nil {
		return
	}

	return
}

func (p *P11) BootstrapCA() (err error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization: []string{"Thales"},
			Country:      []string{"US"},
			Province:     []string{"OR"},
			Locality:     []string{"Portland"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	fmt.Println("Bootstrapping CA")
	// Use the P11 Device for our randomness/entropy
	var rng io.Reader
	if rng, err = p.ctxt11.NewRandomReader(); err != nil {
		return
	}
	var caPriv *rsa.PrivateKey
	if caPriv, err = rsa.GenerateKey(rng, 4096); err != nil {
		return
	}

	// Create CA Cert
	var caCertBytes []byte
	if caCertBytes, err = x509.CreateCertificate(rand.Reader, ca, ca, &caPriv.PublicKey, caPriv); err != nil {
		return
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	if err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	}); err != nil {
		return
	}
	fmt.Printf("making dir: %s", filepath.Dir(p.ca))

	// Save CA Cert
	if err = os.MkdirAll(filepath.Dir(p.ca), 0600); err != nil {
		return
	}
	if err = ioutil.WriteFile(p.ca, caPEM.Bytes(), 0600); err != nil {
		return
	}
	// Generate EST Server Certificate
	var fqdn string
	if fqdn, err = os.Hostname(); err != nil {
		return
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Thales"},
			Country:      []string{"US"},
			Province:     []string{"OR"},
			Locality:     []string{"Portland"},
			CommonName:   fqdn,
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		DNSNames:     []string{fqdn, "localhost", "k8s-kms-plugin-server"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	var serverPriv *rsa.PrivateKey
	var serverCertBytes []byte
	if serverPriv, err = rsa.GenerateKey(rng, 4096); err != nil {
		return
	}

	if serverCertBytes, err = x509.CreateCertificate(rng, cert, ca, &serverPriv.PublicKey, caPriv); err != nil {
		return
	}

	// Save the Server Key and Cert....

	serverCertPEM := new(bytes.Buffer)
	if err = pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	}); err != nil {
		return
	}
	if err = ioutil.WriteFile(p.cert, serverCertPEM.Bytes(), 0600); err != nil {
		return
	}

	serverPrivPEM := new(bytes.Buffer)
	if err = pem.Encode(serverPrivPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPriv),
	}); err != nil {
		return
	}
	if err = ioutil.WriteFile(p.key, serverPrivPEM.Bytes(), 0600); err != nil {
		return
	}

	var serverCert tls.Certificate
	serverCert, err = tls.X509KeyPair(serverCertPEM.Bytes(), serverPrivPEM.Bytes())
	if err != nil {
		return
	}

	p.ServerTLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())
	p.ClientTLS = &tls.Config{
		RootCAs: certpool,
	}

	return
}

func (p *P11) GetCACerts(params operation.GetCACertsParams) middleware.Responder {

	resp := operation.NewGetCACertsOK()
	resp.Payload = ""
	return resp
}

func (p *P11) LoadCA() (err error) {

	return
}

func (p *P11) SimpleEnroll(params operation.SimpleenrollParams, principal interface{}) middleware.Responder {
	panic("implement me")
}

func (p *P11) SimpleReenroll(params operation.SimplereenrollParams) middleware.Responder {
	panic("implement me")
}
