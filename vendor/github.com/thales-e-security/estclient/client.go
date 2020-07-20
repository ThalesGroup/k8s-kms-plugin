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

// Package estclient is minimal EST client SDK (see RFC 7030).
package estclient

import (
	"crypto"
	"crypto/x509"

	"github.com/pkg/errors"
)

// AuthData provides the authentication data offered by the client to the server. Non-nil values will be used during
// authentication.
type AuthData struct {

	// ID is a pre-shared ID used as part of HTTP basic authentication.
	ID *string

	// Secret is a pre-shared secret used as part of HTTP basic authentication.
	Secret *string

	// Key is an existing private key owned by the client. If Key is supplied, ClientCert must also be present. The
	// pair are used to perform client TLS authentication.
	Key crypto.PrivateKey

	// ClientCert is a certificate owned by the client. If ClientCert is supplied, Key must also be present. The
	// pair are used to perform client TLS authentication.
	ClientCert *x509.Certificate

	// Prevent construction using un-keyed fields.
	_ struct{}
}

// EstClient enables clients to request certificates from an EST server.
type EstClient interface {
	// CaCerts retrieves the EST CA certificate (which will sign
	// the apiclient certificates)
	CaCerts() (*CaCertsInfo, error)

	// SimpleEnroll requests a certificate from the EST server.
	SimpleEnroll(authData AuthData, req *x509.CertificateRequest) (*x509.Certificate, error)

	// SimpleReenroll renews a client certificate.
	SimpleReenroll(authData AuthData, req *x509.CertificateRequest) (*x509.Certificate, error)
}

// CaCertsInfo contains the data returned by the EST server when
// calling /cacerts.
type CaCertsInfo struct {

	// EstTA is the trust anchor of the EST system. If the EST CA is a subordinate of
	// this trust anchor, then EstChainCerts should contain the necessary certificates to
	// build a chain from issued certificates through to the EstTA.
	EstTA *x509.Certificate

	// EstChainCerts contains the certificates necessary to construct a chain from
	// the certificates issued by the EST CA through to the EstTA certificiate. This
	// field will be nil or empty if the EstTA is the same certificate as the EST CA.
	EstChainCerts []*x509.Certificate

	// OldWithOld may be present if the EstTA has renewed its certificate. It is a copy
	// of the old EstTA certificate.
	OldWithOld *x509.Certificate

	// OldWithNew may be present if the EstTA has renewed its certificate. It is a certificate
	// containing the public key of the old certificate, signed with the new EstTA key.
	OldWithNew *x509.Certificate

	// NewWithOld may be present if the EstTA has renewed its certificate. It is a certificate
	// containing the new public key of the EstTA, signed with the old key.
	NewWithOld *x509.Certificate
}

// estHTTPClient is the default implementation of the EstClient interface.
type estHTTPClient struct {
	builder apiBuilder
}

// ClientOptions contains configuration settings for building the EST apiclient.
type ClientOptions struct {
	// InsecureSkipVerify, when true, causes the apiclient to accept any TLS server certificate
	// presented by the EST server. As the name suggests, this is insecure and for testing
	// purposes only
	InsecureSkipVerify bool

	// TLSTrustAnchor, if non-nil, designates an explicit trust anchor to use for the
	// TLS session to the EST server.
	TLSTrustAnchor *x509.Certificate
}

// NewEstClient creates a apiclient that communicates with the given host.
// The host string is a domain name with optional ":port" suffix.
func NewEstClient(host string) EstClient {
	return NewEstClientWithOptions(host, ClientOptions{})
}

// NewEstClientWithOptions accepts additional options to configure the EST apiclient.
func NewEstClientWithOptions(host string, options ClientOptions) EstClient {
	swaggerBuilder := swaggerAPIBuilder{
		options: options,
		host:    host,
	}

	return newEstClient(swaggerBuilder)
}

// newEstClient constructs an EST client using the specified server API builder. This should be used
// by unit tests wishing to mock the server interface.
func newEstClient(builder apiBuilder) EstClient {
	return estHTTPClient{builder: builder}
}

// CaCerts implements EstClient.CaCerts
func (c estHTTPClient) CaCerts() (*CaCertsInfo, error) {
	est, err := c.builder.Build(nil, nil)
	if err != nil {
		return nil, err
	}

	res, err := est.CACerts()
	if err != nil {
		return nil, errors.Wrap(err, "failed to request CA certificates")
	}

	return parseCaCerts(res)
}

// SimpleEnroll implements EstClient.SimpleEnroll
func (c estHTTPClient) SimpleEnroll(authData AuthData, req *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := validateAuthData(authData); err != nil {
		return nil, err
	}

	est, err := c.builder.Build(authData.Key, authData.ClientCert)
	if err != nil {
		return nil, err
	}

	data := toBase64(req.Raw)
	res, err := est.SimpleEnroll(authData, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to request certificate")
	}

	return readCertificate(res)
}

// SimpleReenroll implements EstClient.SimpleReenroll
func (c estHTTPClient) SimpleReenroll(authData AuthData, req *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := validateAuthData(authData); err != nil {
		return nil, err
	}

	est, err := c.builder.Build(authData.Key, authData.ClientCert)
	if err != nil {
		return nil, err
	}

	data := toBase64(req.Raw)
	res, err := est.SimpleReEnroll(authData, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to request certificate")
	}

	return readCertificate(res)
}
