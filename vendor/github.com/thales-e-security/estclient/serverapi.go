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
	"crypto"
	"crypto/x509"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	"github.com/thales-e-security/estclient/apiclient"
	"github.com/thales-e-security/estclient/apiclient/operation"
)

// A serverAPI instance represents and EST server.
type serverAPI interface {

	// CACerts retrieves the CA certificates from the EST server. The result is the raw response from the server.
	CACerts() (string, error)

	// SimpleEnroll triggers the simple enroll endpoint of the EST server. certRequest should be a base64-encoded
	// DER-format PKCS#10 certificate request. The result is the raw response from the server.
	SimpleEnroll(authData AuthData, certRequest string) (string, error)

	// SimpleReEnroll triggers the simple re-enroll endpoint of the EST server. certRequest should be a base64-encoded
	// DER-format PKCS#10 certificate request. The result is the raw response from the server.
	SimpleReEnroll(authData AuthData, certRequest string) (string, error)
}

// An apiBuilder creates serverAPI instances.
type apiBuilder interface {

	// Build creates a serverAPI instance, optionally using the supplied private key and certificate
	// for client authentication.
	Build(currentKey crypto.PrivateKey, currentCert *x509.Certificate) (serverAPI, error)
}

type swaggerAPIBuilder struct {
	options ClientOptions
	host    string
}

func (s swaggerAPIBuilder) Build(currentKey crypto.PrivateKey, currentCert *x509.Certificate) (serverAPI, error) {
	o := httptransport.TLSClientOptions{
		InsecureSkipVerify: s.options.InsecureSkipVerify,
		LoadedCA:           s.options.TLSTrustAnchor,
	}

	if currentKey != nil && currentCert != nil {
		o.LoadedKey = currentKey
		o.LoadedCertificate = currentCert
	}

	tlsClient, err := httptransport.TLSClient(o)
	if err != nil {
		return nil, errors.Wrap(err, "could not create TLS apiclient")
	}

	cfg := apiclient.DefaultTransportConfig()
	rt := httptransport.NewWithClient(s.host, cfg.BasePath, cfg.Schemes, tlsClient)

	// For now, we just process PKCS7 as text and base64-decode later
	rt.Consumers["application/pkcs7-mime"] = runtime.TextConsumer()

	// Ditto for PKCS10
	rt.Producers["application/pkcs10"] = runtime.TextProducer()
	return swaggerServerAPI{client: apiclient.New(rt, strfmt.Default).Operation}, nil
}

type swaggerServerAPI struct {
	client *operation.Client
}

func (s swaggerServerAPI) CACerts() (string, error) {
	params := operation.NewCacertsParams()
	res, err := s.client.Cacerts(params)

	if err != nil {
		return "", err
	}

	return res.Payload, nil
}

func (s swaggerServerAPI) SimpleEnroll(authData AuthData, certRequest string) (string, error) {
	var httpAuth runtime.ClientAuthInfoWriter
	if authData.ID != nil && authData.Secret != nil {
		httpAuth = httptransport.BasicAuth(*authData.ID, *authData.Secret)
	}

	params := operation.NewSimpleenrollParams()
	params.Certrequest = certRequest

	res, err := s.client.Simpleenroll(params, httpAuth)
	if err != nil {
		return "", err
	}

	return res.Payload, nil
}

func (s swaggerServerAPI) SimpleReEnroll(authData AuthData, certRequest string) (string, error) {
	var httpAuth runtime.ClientAuthInfoWriter
	if authData.ID != nil && authData.Secret != nil {
		httpAuth = httptransport.BasicAuth(*authData.ID, *authData.Secret)
	}

	params := operation.NewSimplereenrollParams()
	params.Certrequest = certRequest

	res, err := s.client.Simplereenroll(params, httpAuth)
	if err != nil {
		return "", err
	}

	return res.Payload, nil
}
