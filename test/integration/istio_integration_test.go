/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package integration

import (
	"context"
	"reflect"
	"testing"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	"github.com/ThalesGroup/k8s-kms-plugin/pkg/providers"
)

func TestP11_GenerateDEK(t *testing.T) {
	td := setupSoftHSMTestCase(t)
	defer td(t)
	type fields struct {
		keyId      []byte
		config     *crypto11.Config
		ctx        *crypto11.Context
		encryptors map[string]gose.JweEncryptor
		decryptors map[string]gose.JweDecryptor
		createKey  bool
	}
	type args struct {
		ctx     context.Context
		request *istio.GenerateDEKRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				keyId:      testKid,
				config:     testConfig,
				ctx:        testCtx,
				decryptors: nil,
				encryptors: nil,
				createKey:  true,
			},
			args: args{
				ctx: context.Background(),
				request: &istio.GenerateDEKRequest{

					KekKid: testKid,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := providers.NewP11(
				tt.fields.config,
				tt.fields.createKey,
				"",    // kekkeyid
				"",    // k8sKekLabel
				"",    // hmacKeyLabel
				"",    // hmacCkaId
				"",    // algorithm
				false, // isKeyRotation
				nil,   // oldConfig
				"",    // oldKekkeyid
				"",    // oldKekCkaLabel
				"",    // oldHmacKeyLabel
				"",    // oldHmacCkaId
				"",    // oldAlgorithm
			)
			if err != nil {
				t.Fatalf("Unable to create P11 instance, err: %v", err)
			}

			p.SetEncryptors(tt.fields.encryptors)
			p.SetDecryptors(tt.fields.decryptors)
			p.SetContext(tt.fields.ctx)

			gotResp, err := p.GenerateDEK(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDEK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(gotResp.EncryptedDekBlob) == 0 {
				t.Errorf("encrypted blob is nil/empty")
				return
			}
		})
	}
}

func TestP11_GenerateSKey(t *testing.T) {
	td := setupSoftHSMTestCase(t)
	defer td(t)
	type fields struct {
		keyId      []byte
		config     *crypto11.Config
		ctx        *crypto11.Context
		encryptors map[string]gose.JweEncryptor
		decryptors map[string]gose.JweDecryptor
		createKey  bool
	}
	type args struct {
		ctx     context.Context
		request *istio.GenerateSKeyRequest
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantResp *istio.GenerateSKeyResponse
		wantErr  bool
	}{
		{
			name: "OK",
			fields: fields{
				keyId:  testKid,
				config: testConfig,
				ctx:    testCtx,

				createKey: true,
			},
			args: args{
				ctx: context.Background(),
				request: &istio.GenerateSKeyRequest{
					Size:             4096,
					Kind:             istio.KeyKind_RSA,
					EncryptedDekBlob: testWrappedDEK,
					KekKid:           testKid,
				},
			},
			wantResp: nil,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := providers.NewP11(
				tt.fields.config,
				tt.fields.createKey,
				"",    // kekkeyid
				"",    // k8sKekLabel
				"",    // hmacKeyLabel
				"",    // hmacCkaId
				"",    // algorithm
				false, // isKeyRotation
				nil,   // oldConfig
				"",    // oldKekkeyid
				"",    // oldKekCkaLabel
				"",    // oldHmacKeyLabel
				"",    // oldHmacCkaId
				"",    // oldAlgorithm
			)
			if err != nil {
				t.Fatalf("Unable to create P11 instance, err: %v", err)
			}

			p.SetEncryptors(tt.fields.encryptors)
			p.SetDecryptors(tt.fields.decryptors)
			p.SetContext(tt.fields.ctx)

			gotResp, err := p.GenerateSKey(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {

				t.Errorf("GenerateSKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResp, tt.wantResp) {
				t.Errorf("GenerateSKey() gotResp = %v, want %v", gotResp, tt.wantResp)
			}
		})
	}
}

func TestP11_ImportCACert(t *testing.T) {
	td := setupSoftHSMTestCase(t)
	defer td(t)
	type fields struct {
		kid        []byte
		cid        []byte
		config     *crypto11.Config
		ctx        *crypto11.Context
		encryptors map[string]gose.JweEncryptor
		decryptors map[string]gose.JweDecryptor
		createKey  bool
	}
	type args struct {
		ctx     context.Context
		request *istio.ImportCACertRequest
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantResp *istio.ImportCACertResponse
		wantErr  bool
	}{
		{
			name: "OK",
			fields: fields{
				kid:        testKid,
				cid:        testCid,
				config:     testConfig,
				ctx:        testCtx,
				encryptors: testEncryptor,
				decryptors: nil,
				createKey:  false,
			},
			args: args{
				ctx: context.Background(),
				request: &istio.ImportCACertRequest{
					CaId:       testCid,
					CaCertBlob: testCertPem,
				},
			},
			wantResp: &istio.ImportCACertResponse{
				Success: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := providers.NewP11(
				tt.fields.config,
				tt.fields.createKey,
				"",    // kekkeyid
				"",    // k8sKekLabel
				"",    // hmacKeyLabel
				"",    // hmacCkaId
				"",    // algorithm
				false, // isKeyRotation
				nil,   // oldConfig
				"",    // oldKekkeyid
				"",    // oldKekCkaLabel
				"",    // oldHmacKeyLabel
				"",    // oldHmacCkaId
				"",    // oldAlgorithm
			)
			if err != nil {
				t.Fatalf("Unable to create P11 instance, err: %v", err)
			}

			p.SetKekKeyIdFromBytes(tt.fields.kid)
			p.SetCID(tt.fields.cid)
			p.SetEncryptors(tt.fields.encryptors)
			p.SetDecryptors(tt.fields.decryptors)
			p.SetContext(tt.fields.ctx)

			gotResp, err := p.ImportCACert(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ImportCACert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResp, tt.wantResp) {
				t.Errorf("ImportCACert() gotResp = %v, want %v", gotResp, tt.wantResp)
			}
		})
	}
}

func TestP11_LoadDEK(t *testing.T) {
	td := setupSoftHSMTestCase(t)
	defer td(t)
	type fields struct {
		keyId      []byte
		config     *crypto11.Config
		ctx        *crypto11.Context
		encryptors map[string]gose.JweEncryptor
		decryptors map[string]gose.JweDecryptor
		createKey  bool
	}
	type args struct {
		ctx     context.Context
		request *istio.LoadSKeyRequest
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantResp *istio.LoadSKeyResponse
		wantErr  bool
	}{
		{
			name: "OK",
			fields: fields{
				keyId:      testKid,
				config:     testConfig,
				ctx:        testCtx,
				encryptors: testEncryptor,
				decryptors: nil,
				createKey:  false,
			},
			args: args{
				ctx: context.Background(),
				request: &istio.LoadSKeyRequest{

					EncryptedDekBlob:  testWrappedDEK,
					EncryptedSkeyBlob: testWrappedSKey,
				},
			},
			wantResp: nil,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := providers.NewP11(
				tt.fields.config,
				tt.fields.createKey,
				"",    // kekkeyid
				"",    // k8sKekLabel
				"",    // hmacKeyLabel
				"",    // hmacCkaId
				"",    // algorithm
				false, // isKeyRotation
				nil,   // oldConfig
				"",    // oldKekkeyid
				"",    // oldKekCkaLabel
				"",    // oldHmacKeyLabel
				"",    // oldHmacCkaId
				"",    // oldAlgorithm
			)
			if err != nil {
				t.Fatalf("Unable to create P11 instance, err: %v", err)
			}

			p.SetEncryptors(tt.fields.encryptors)
			p.SetDecryptors(tt.fields.decryptors)
			p.SetContext(tt.fields.ctx)

			gotResp, err := p.LoadSKey(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadDEK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResp, tt.wantResp) {
				t.Errorf("LoadDEK() gotResp = %v, want %v", gotResp, tt.wantResp)
			}
		})
	}
}
