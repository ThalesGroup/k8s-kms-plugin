package providers

import (
	"context"
	"crypto"
	"crypto/x509"
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/kms/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/keystore"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gotest.tools/assert"
	"os"
	"testing"
	"time"
)

const (
	testKEK         = "b144efd3-4501-47ea-a6a8-30a104f80df6"
	testRootKeyPair = "305c2df0-b0e4-433e-8054-f2b4b05a5754"
	testCertificate = "e24d4136-c750-4e10-ba25-e0935a962dee"

	testDEKName = "63631c88-d466-471c-b000-f369b7609bdf"
)

var (
	testConfig *crypto11.Config
	testCtx11  *crypto11.Context
	testCtx    context.Context
	testP11    *P11
	testStore  keystore.KeyStore

	testWrappedIntKek []byte
)

func init() {
	testConfig = &crypto11.Config{
		Path:       os.Getenv("P11_LIBRARY"),
		TokenLabel: os.Getenv("P11_TOKEN"),
		Pin:        os.Getenv("P11_PIN"),
	}

	var err error
	if testCtx11, err = crypto11.Configure(testConfig); err != nil {
		panic(err)
	}

	testStore = keystore.NewMemoryPrivateKeyStore(testWrappedIntKek)

}
func setup(t testing.TB) func(t testing.TB) {
	var err error

	if testP11, err = NewP11(testConfig, testStore, nil, true); err != nil {
		t.Fatal(err)
	}
	return func(t testing.TB) {

	}
}

func TestP11_CreateCryptoKey(t *testing.T) {
	td := setup(t)
	defer td(t)
	type fields struct {
		config     *crypto11.Config
		ctx        *crypto11.Context
		encryptors map[string]gose.JweEncryptor
		decryptors map[string]gose.JweDecryptor
		signers    map[string]gose.SigningKey
		aeGen      *gose.AuthenticatedEncryptionKeyGenerator
		rsGen      *gose.RsaSigningKeyGenerator
		rkdGen     *gose.RsaKeyDecryptionKeyGenerator
		esGen      *gose.ECDSASigningKeyGenerator
		createKey  bool
		pubKey     crypto.PublicKey
		rootCert   *x509.Certificate
		intCert    *x509.Certificate
		intJwk     jose.Jwk
		store      keystore.KeyStore
	}
	type args struct {
		ctx     context.Context
		request *kms.CreateCryptoKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantKey *kms.CryptoKey
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				config: testConfig,
				ctx:    testCtx11,
				store:  testStore,
			},
			args: args{
				ctx: testCtx,
				request: &kms.CreateCryptoKeyRequest{
					CryptoKeyId: testDEKName,
					CryptoKey: &kms.CryptoKey{
						Name:       testDEKName,
						Purpose:    kms.CryptoKey_ENCRYPT_DECRYPT,
						CreateTime: timestamppb.New(time.Now()),
					},
				},
			},
			wantKey: &kms.CryptoKey{
				Name:    testDEKName,
				Purpose: kms.CryptoKey_ENCRYPT_DECRYPT,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &P11{
				config:     tt.fields.config,
				ctx:        tt.fields.ctx,
				encryptors: tt.fields.encryptors,
				decryptors: tt.fields.decryptors,
				signers:    tt.fields.signers,
				aeGen:      tt.fields.aeGen,
				rsGen:      tt.fields.rsGen,
				rkdGen:     tt.fields.rkdGen,
				esGen:      tt.fields.esGen,
				autoCreate: tt.fields.createKey,
				pubKey:     tt.fields.pubKey,
				rootCert:   tt.fields.rootCert,
				intCert:    tt.fields.intCert,
				intKek:     tt.fields.intJwk,
				store:      tt.fields.store,
			}
			gotKey, err := p.CreateCryptoKey(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCryptoKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotKey == nil && !tt.wantErr {
				t.Errorf("CreateCryptoKey() gotKey = %v, want %v", gotKey, tt.wantKey)
			} else {
				assert.DeepEqual(t, gotKey.Name, tt.wantKey.Name)
				assert.DeepEqual(t, gotKey.Purpose, tt.wantKey.Purpose)
			}

		})
	}
}
