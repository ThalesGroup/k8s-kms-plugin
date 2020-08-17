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
	"bytes"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/utils"
	"path/filepath"
	"reflect"
	"testing"
)

var (
	testAEGen         = &gose.AuthenticatedEncryptionKeyGenerator{}
	testRootKek       jose.Jwk
	testIntKek        jose.Jwk
	testAEKey         jose.Jwk
	testEphemeralKey  jose.Jwk
	testEncryptor     gose.JweEncryptor
	testDecryptor     gose.JweDecryptor
	testFileDir       = filepath.Join("testdata", ".keystore")
	testWrappedIntKek []byte
)

const (
	testEphemeralKeyName = "test-ephemeral-key"
	testAEKeyName        = "test-ae-key"
	testRootKekValue     = `{"key_ops":["encrypt","decrypt"],"alg":"A256GCM","kid":"9a5dcf952612401aa42643189733ddf3fdb29bebcbeb8a99f3731b4b440992e3","k":"q9TMHTUc5Ajli3utbNlhLe2rwPkSBASByNucTlhoWGA","kty":"oct"}`
	testIntKekValue      = `{"key_ops":["encrypt","decrypt"],"alg":"A256GCM","kid":"6f1fc3f90ca35921fc3c213b8d96340b00c3dd2d47ed33796ad07ac41f1744f9","k":"ivQlTzZx2dEoyw4-ZEjCJPoFJVKBkcbEOKxIYaywczU","kty":"oct"}`
	testAEKeyValue       = `{"key_ops":["encrypt","decrypt"],"alg":"A256GCM","kid":"258aa30bf47e8b375406477cd56323ca68c192d46f737e95d381698d53b2ac56","k":"YjDgXcV0LspUiWZ6Iib-I3BkLseGazQcKnBXZ_XiZpY","kty":"oct"}`
)

func init() {

}
func setup(t testing.TB) func(t testing.TB) {
	var err error
	if testIntKek, err = gose.LoadJwk(bytes.NewReader([]byte(testIntKekValue)), utils.AuthenticatedEncryptedKeyOperations); err != nil {
		t.Fatal(err)
	}
	var iaead gose.AuthenticatedEncryptionKey
	if iaead, err = gose.NewAesGcmCryptorFromJwk(testIntKek, utils.AuthenticatedEncryptedKeyOperations); err != nil {
		t.Fatal(err)
	}
	testEncryptor = gose.NewJweDirectEncryptorImpl(iaead)
	testDecryptor = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{iaead})
	var fs *FileStore
	if fs, err = NewFilePrivateKeyStore(testFileDir); err != nil {
		t.Fatal(err)
	}
	if err = fs.LoadIntKek(testIntKek); err != nil{
		t.Fatal(err)
	}
	// use a fake RootKek to wrap the IntKek
	if testRootKek, err = gose.LoadJwk(bytes.NewReader([]byte(testRootKekValue)), utils.AuthenticatedEncryptedKeyOperations); err != nil {
		t.Fatal(err)
	}
	var raead gose.AuthenticatedEncryptionKey
	if raead, err = gose.NewAesGcmCryptorFromJwk(testRootKek, utils.AuthenticatedEncryptedKeyOperations); err != nil {
		t.Fatal(err)
	}
	var rootEncryptor gose.JweEncryptor
	rootEncryptor = gose.NewJweDirectEncryptorImpl(raead)
	var testWrappedIntKekString string
	if testWrappedIntKekString, err = rootEncryptor.Encrypt([]byte(testIntKekValue), nil); err != nil {
		t.Fatal(err)
	}
	testWrappedIntKek = []byte(testWrappedIntKekString)
	if err = fs.StoreIntKek(testWrappedIntKek); err != nil {
		t.Fatal(err)
	}

	// Load the test
	if testAEKey, err = gose.LoadJwk(bytes.NewReader([]byte(testAEKeyValue)), []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}); err != nil {
		t.Fatal(err)
	}
	if err = fs.Store(testAEKeyName, testAEKey, true); err != nil {
		t.Fatal(err)
	}

	if _, testEphemeralKey, err = testAEGen.Generate(jose.AlgA256GCM, []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}); err != nil {
		t.Fatal(t)
	}

	return func(t testing.TB) {
		if err = fs.Store(testAEKeyName, testAEKey, true); err != nil {
			panic(err)
		}
	}
}

func TestFileStore_StoreIntKek(t *testing.T) {
	td := setup(t)
	defer td(t)
	type fields struct {
		Root      string
		intKek    jose.Jwk
		encryptor gose.JweEncryptor
		decryptor gose.JweDecryptor
	}
	type args struct {
		wrappedIntKek []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			args: args{
				wrappedIntKek: testWrappedIntKek,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &FileStore{
				Root:      tt.fields.Root,
				intKek:    tt.fields.intKek,
				encryptor: tt.fields.encryptor,
				decryptor: tt.fields.decryptor,
			}
			if err := fs.StoreIntKek(tt.args.wrappedIntKek); (err != nil) != tt.wantErr {
				t.Errorf("StoreIntKek() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFileStore_RetrieveStoreIntKek(t *testing.T) {
	td := setup(t)
	defer td(t)
	type fields struct {
		Root      string
		intKek    jose.Jwk
		encryptor gose.JweEncryptor
		decryptor gose.JweDecryptor
	}
	tests := []struct {
		name              string
		fields            fields
		wantWrappedIntKek []byte
		wantErr           bool
	}{
		{
			name: "OK",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			wantWrappedIntKek: testWrappedIntKek,
			wantErr:           false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &FileStore{
				Root:      tt.fields.Root,
				intKek:    tt.fields.intKek,
				encryptor: tt.fields.encryptor,
				decryptor: tt.fields.decryptor,
			}
			gotWrappedIntKek, err := fs.RetrieveStoreIntKek()
			if (err != nil) != tt.wantErr {
				t.Errorf("RetrieveStoreIntKek() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotWrappedIntKek, tt.wantWrappedIntKek) {
				t.Errorf("RetrieveStoreIntKek() gotWrappedIntKek = %v, want %v", gotWrappedIntKek, tt.wantWrappedIntKek)
			}
		})
	}
}

func TestFileStore_LoadIntKek(t *testing.T) {
	td := setup(t)
	defer td(t)
	type fields struct {
		Root      string
		intKek    jose.Jwk
		encryptor gose.JweEncryptor
		decryptor gose.JweDecryptor
	}
	type args struct {
		jwk jose.Jwk
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		//{
		//	name: "OK",
		//	fields: fields{
		//		Root:       testFileDir,
		//		intKek: testintKek,
		//		encryptor:  nil,
		//		decryptor:  nil,
		//	},
		//	args: args{
		//		jwk: testintKek,
		//	},
		//	wantErr: false,
		//},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &FileStore{
				Root:      tt.fields.Root,
				intKek:    tt.fields.intKek,
				encryptor: tt.fields.encryptor,
				decryptor: tt.fields.decryptor,
			}
			if err := fs.LoadIntKek(tt.args.jwk); (err != nil) != tt.wantErr {
				t.Errorf("LoadIntKek() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestFileStore_Store(t *testing.T) {
	td := setup(t)
	defer td(t)
	type fields struct {
		Root      string
		intKek    jose.Jwk
		encryptor gose.JweEncryptor
		decryptor gose.JweDecryptor
	}
	type args struct {
		name      string
		jwk       jose.Jwk
		overwrite bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Store new",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			args: args{
				name:      testEphemeralKeyName,
				jwk:       testEphemeralKey,
				overwrite: true,
			},
			wantErr: false,
		}, {
			name: "Store existing - overwrite false",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			args: args{
				name:      testAEKeyName,
				jwk:       testAEKey,
				overwrite: false,
			},
			wantErr: true,
		}, {
			name: "Store existing - overwrite true",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			args: args{
				name:      testEphemeralKeyName,
				jwk:       testEphemeralKey,
				overwrite: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &FileStore{
				Root:      tt.fields.Root,
				intKek:    tt.fields.intKek,
				encryptor: tt.fields.encryptor,
				decryptor: tt.fields.decryptor,
			}
			if err := fs.Store(tt.args.name, tt.args.jwk, tt.args.overwrite); (err != nil) != tt.wantErr {
				t.Errorf("Store() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFileStore_Exists(t *testing.T) {
	td := setup(t)
	defer td(t)
	type fields struct {
		Root      string
		intKek    jose.Jwk
		encryptor gose.JweEncryptor
		decryptor gose.JweDecryptor
	}
	type args struct {
		name string
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantExists bool
		wantErr    bool
	}{
		{
			name: "Found",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			args: args{
				name: testAEKeyName,
			},
			wantExists: true,
			wantErr:    false,
		}, {
			name: "Missing",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			args: args{
				name: "something not real...",
			},
			wantExists: false,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &FileStore{
				Root:      tt.fields.Root,
				intKek:    tt.fields.intKek,
				encryptor: tt.fields.encryptor,
				decryptor: tt.fields.decryptor,
			}
			gotExists, err := fs.Exists(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("Exists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotExists != tt.wantExists {
				t.Errorf("Exists() gotExists = %v, want %v", gotExists, tt.wantExists)
			}
		})
	}
}

func TestFileStore_Remove(t *testing.T) {
	td := setup(t)
	defer td(t)
	type fields struct {
		Root      string
		intKek    jose.Jwk
		encryptor gose.JweEncryptor
		decryptor gose.JweDecryptor
	}
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			args: args{
				name: testEphemeralKeyName,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &FileStore{
				Root:      tt.fields.Root,
				intKek:    tt.fields.intKek,
				encryptor: tt.fields.encryptor,
				decryptor: tt.fields.decryptor,
			}
			if err := fs.Remove(tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("Remove() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestFileStore_RemoveAll(t *testing.T) {
	td := setup(t)
	defer td(t)
	type fields struct {
		Root      string
		intKek    jose.Jwk
		encryptor gose.JweEncryptor
		decryptor gose.JweDecryptor
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &FileStore{
				Root:      tt.fields.Root,
				intKek:    tt.fields.intKek,
				encryptor: tt.fields.encryptor,
				decryptor: tt.fields.decryptor,
			}
			if err := fs.RemoveAll(); (err != nil) != tt.wantErr {
				t.Errorf("RemoveAll() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFileStore_Retrieve(t *testing.T) {
	td := setup(t)
	defer td(t)
	type fields struct {
		Root      string
		intKek    jose.Jwk
		encryptor gose.JweEncryptor
		decryptor gose.JweDecryptor
	}
	type args struct {
		name   string
		keyOps []jose.KeyOps
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantJwk jose.Jwk
		wantErr bool
	}{
		{
			name: "Retrieve Existing Key",
			fields: fields{
				Root: testFileDir,
				intKek: testIntKek,
				encryptor: testEncryptor,
				decryptor: testDecryptor,
			},
			args: args{
				name:   testAEKeyName,
				keyOps: []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt},
			},
			wantJwk: testAEKey,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &FileStore{
				Root:      tt.fields.Root,
				intKek:    tt.fields.intKek,
				encryptor: tt.fields.encryptor,
				decryptor: tt.fields.decryptor,
			}
			gotJwk, err := fs.Retrieve(tt.args.name, tt.args.keyOps)
			if (err != nil) != tt.wantErr {
				t.Errorf("Retrieve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotJwk, tt.wantJwk) {
				t.Errorf("Retrieve() gotJwk = %v, want %v", gotJwk, tt.wantJwk)
			}
		})
	}
}