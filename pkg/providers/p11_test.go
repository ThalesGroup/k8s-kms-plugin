package providers

import (
	"context"
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1"
	"os"
	"testing"
)

var testConfig *crypto11.Config
var testCtx *crypto11.Context
var testEncryptedBlob string
var testPlainMessage []byte

func setupSoftHSMTestCase(t testing.TB) func(t testing.TB) {

	// logrus.SetLevel(logrus.DebugLevel)
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

func TestP11_Encrypt(t *testing.T) {
	td := setupSoftHSMTestCase(t)
	defer td(t)
	type fields struct {
		keyId     []byte
		keyLabel  []byte
		config    *crypto11.Config
		ctx       *crypto11.Context
		encryptor gose.JweEncryptor
		decryptor gose.JweDecryptor
		createKey bool
	}
	type args struct {
		ctx context.Context
		req *k8s.EncryptRequest
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantResp *k8s.EncryptResponse
		wantErr  bool
	}{
		{
			name: "Happy Path - create default",
			fields: fields{
				config:    testConfig,
				ctx:       testCtx,
				keyId:     []byte(defaultkeyId),
				keyLabel:  []byte(defaultkeyLabel),
				createKey: true,
			},
			args: args{
				ctx: context.Background(),
				req: &k8s.EncryptRequest{
					Version: "1",
					Plain:   testPlainMessage,
				},
			},
			wantResp: &k8s.EncryptResponse{
				Cipher: []byte(testEncryptedBlob),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &P11{
				keyId:     tt.fields.keyId,
				keyLabel:  tt.fields.keyLabel,
				config:    tt.fields.config,
				ctx:       tt.fields.ctx,
				encryptor: tt.fields.encryptor,
				decryptor: tt.fields.decryptor,
				createKey: tt.fields.createKey,
			}
			gotResp, err := p.Encrypt(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			var gotClearResp *k8s.DecryptResponse
			if gotClearResp, err = p.Decrypt(context.Background(), &k8s.DecryptRequest{
				Cipher: gotResp.Cipher,
			}); err != nil {
				t.Errorf("Unable to decrypt the payload... danger!!!")
				return
			}
			if string(gotClearResp.Plain) != string(testPlainMessage) {
				t.Errorf("bad decrypt... something really wrong!!!")
				return
			}

		})
	}
}
