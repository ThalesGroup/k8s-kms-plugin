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
	"crypto/tls"
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/go-openapi/runtime/middleware"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/operations/operation"
	"os"
	"reflect"
	"testing"
)
var testConfig *crypto11.Config
var testCtx *crypto11.Context
func TestNewP11EST(t *testing.T) {
	type args struct {
		ca     string
		key    string
		cert   string
		config *crypto11.Config
	}
	tests := []struct {
		name    string
		args    args
		wantE   *P11
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotE, err := NewP11EST(tt.args.ca, tt.args.key, tt.args.cert, tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewP11EST() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotE, tt.wantE) {
				t.Errorf("NewP11EST() gotE = %v, want %v", gotE, tt.wantE)
			}
		})
	}
}

func TestP11_BootstrapCA(t *testing.T) {
	type fields struct {
		ca         string
		key        string
		cert       string
		ctxt11     *crypto11.Context
		config     *crypto11.Config
		ServerTLS  *tls.Config
		ClientTLS  *tls.Config
		serverCert *tls.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &P11{
				ca:         tt.fields.ca,
				key:        tt.fields.key,
				cert:       tt.fields.cert,
				ctxt11:     tt.fields.ctxt11,
				config:     tt.fields.config,
				ServerTLS:  tt.fields.ServerTLS,
				ClientTLS:  tt.fields.ClientTLS,
				serverCert: tt.fields.serverCert,
			}
			if err := p.BootstrapCA(); (err != nil) != tt.wantErr {
				t.Errorf("BootstrapCA() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestP11_GetCACerts(t *testing.T) {
	type fields struct {
		ca         string
		key        string
		cert       string
		ctxt11     *crypto11.Context
		config     *crypto11.Config
		ServerTLS  *tls.Config
		ClientTLS  *tls.Config
		serverCert *tls.Certificate
	}
	type args struct {
		params operation.GetCACertsParams
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   middleware.Responder
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &P11{
				ca:         tt.fields.ca,
				key:        tt.fields.key,
				cert:       tt.fields.cert,
				ctxt11:     tt.fields.ctxt11,
				config:     tt.fields.config,
				ServerTLS:  tt.fields.ServerTLS,
				ClientTLS:  tt.fields.ClientTLS,
				serverCert: tt.fields.serverCert,
			}
			if got := p.GetCACerts(tt.args.params); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetCACerts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestP11_LoadCA(t *testing.T) {
	type fields struct {
		ca         string
		key        string
		cert       string
		ctxt11     *crypto11.Context
		config     *crypto11.Config
		ServerTLS  *tls.Config
		ClientTLS  *tls.Config
		serverCert *tls.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &P11{
				ca:         tt.fields.ca,
				key:        tt.fields.key,
				cert:       tt.fields.cert,
				ctxt11:     tt.fields.ctxt11,
				config:     tt.fields.config,
				ServerTLS:  tt.fields.ServerTLS,
				ClientTLS:  tt.fields.ClientTLS,
				serverCert: tt.fields.serverCert,
			}
			if err := p.LoadCA(); (err != nil) != tt.wantErr {
				t.Errorf("LoadCA() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestP11_SimpleEnroll(t *testing.T) {
	type fields struct {
		ca         string
		key        string
		cert       string
		ctxt11     *crypto11.Context
		config     *crypto11.Config
		ServerTLS  *tls.Config
		ClientTLS  *tls.Config
		serverCert *tls.Certificate
	}
	type args struct {
		params    operation.SimpleenrollParams
		principal interface{}
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   middleware.Responder
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &P11{
				ca:         tt.fields.ca,
				key:        tt.fields.key,
				cert:       tt.fields.cert,
				ctxt11:     tt.fields.ctxt11,
				config:     tt.fields.config,
				ServerTLS:  tt.fields.ServerTLS,
				ClientTLS:  tt.fields.ClientTLS,
				serverCert: tt.fields.serverCert,
			}
			if got := p.SimpleEnroll(tt.args.params, tt.args.principal); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SimpleEnroll() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestP11_SimpleReenroll(t *testing.T) {
	type fields struct {
		ca         string
		key        string
		cert       string
		ctxt11     *crypto11.Context
		config     *crypto11.Config
		ServerTLS  *tls.Config
		ClientTLS  *tls.Config
		serverCert *tls.Certificate
	}
	type args struct {
		params operation.SimplereenrollParams
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   middleware.Responder
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &P11{
				ca:         tt.fields.ca,
				key:        tt.fields.key,
				cert:       tt.fields.cert,
				ctxt11:     tt.fields.ctxt11,
				config:     tt.fields.config,
				ServerTLS:  tt.fields.ServerTLS,
				ClientTLS:  tt.fields.ClientTLS,
				serverCert: tt.fields.serverCert,
			}
			if got := p.SimpleReenroll(tt.args.params); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SimpleReenroll() = %v, want %v", got, tt.want)
			}
		})
	}
}


func setupSoftHSMTestCase(t testing.TB) func(t testing.TB) {

	var err error
	if os.Getenv("P11_LIBRARY") == "" {
		t.Skip("No P11_LIBRARY provided, skipping")
	}
	// Allow the MasterKey to be created if missing to be created
	testConfig = &crypto11.Config{
		Path:       os.Getenv("P11_LIBRARY"),
		TokenLabel: os.Getenv("P11_TOKEN"),
		Pin:        os.Getenv("P11_PIN"),
	}
	if testCtx, err = crypto11.Configure(testConfig); err != nil {
		t.Fatal(err)
	}

	// Create the default key just so we can do some practical encrypt decrypting without having to mock..

	var handle *crypto11.SecretKey
	if handle, err = testCtx.GenerateSecretKeyWithLabel([]byte(t.Name()), []byte(defaultkeyLabel), 256, crypto11.CipherAES); err != nil {
		t.Fatal(err)
	}
	rng, _ := testCtx.NewRandomReader()
	aead, _ := handle.NewGCM()
	taead, _ := gose.NewAesGcmCryptor(aead, rng, t.Name(), jose.AlgA256GCM, keyOps)
	testPlainMessage = []byte("Hello World, I'm a DEK, Secret, or something sensitive")
	testEncryptedBlob, err = gose.NewJweDirectEncryptorImpl(taead).Encrypt(testPlainMessage, nil)

	return func(t testing.TB) {
		// teardown goes here as needed
		var keys []*crypto11.SecretKey
		if keys, err = testCtx.FindAllKeys(); err != nil {
			return
		}
		for _, key := range keys {
			_ = key.Delete()
		}
	}
}