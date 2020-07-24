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
	"github.com/go-openapi/runtime/middleware"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/operations/operation"
	"reflect"
	"testing"
)

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