package providers

import (
	"context"
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/google/uuid"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1"
	"os"
	"reflect"
	"testing"
)

var (
	testAESKey          *crypto11.SecretKey
	testAESKeyJWK       jose.Jwk
	testAESKeyJWKString string
	testConfig          *crypto11.Config
	testCtx             *crypto11.Context
	testDecryptor       gose.JweDecryptor
	testEncryptedBlob   string
	testEncryptor       gose.JweEncryptor
	testKid, testLabel  []byte
	testPlainMessage    []byte
	testRSAKEY          crypto11.SignerDecrypter
	testWrappedDEK      []byte
	testWrappedSEK      []byte
)

func init() {
	testConfig = &crypto11.Config{
		Path:       os.Getenv("P11_LIBRARY"),
		TokenLabel: os.Getenv("P11_TOKEN"),
		Pin:        os.Getenv("P11_PIN"),
	}
	var err error
	if testCtx, err = crypto11.Configure(testConfig); err != nil {
		panic(err)
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
				keyId:     []byte("afdjaklfjdaskl"),
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

func TestP11_GenerateDEK(t *testing.T) {
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
				keyId:     testKid,
				keyLabel:  testLabel,
				config:    testConfig,
				ctx:       testCtx,
				decryptor: nil,
				encryptor: nil,
				createKey: true,
			},
			args: args{
				ctx: context.Background(),
				request: &istio.GenerateDEKRequest{
					Size: 32,
					Kind: istio.KeyKind_AES,
				},
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

func TestP11_GenerateSEK(t *testing.T) {
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
		ctx     context.Context
		request *istio.GenerateSEKRequest
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantResp *istio.GenerateSEKResponse
		wantErr  bool
	}{
		{
			name: "OK",
			fields: fields{
				keyId:     testKid,
				keyLabel:  testLabel,
				config:    testConfig,
				ctx:       testCtx,
				encryptor: nil,
				decryptor: nil,
				createKey: true,
			},
			args: args{
				ctx: context.Background(),
				request: &istio.GenerateSEKRequest{
					Size:             4096,
					Kind:             istio.KeyKind_RSA,
					EncryptedDekBlob: testWrappedDEK,
				},
			},
			wantResp: nil,
			wantErr:  false,
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
			gotResp, err := p.GenerateSEK(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSEK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResp, tt.wantResp) {
				t.Errorf("GenerateSEK() gotResp = %v, want %v", gotResp, tt.wantResp)
			}
		})
	}
}

func TestP11_LoadDEK(t *testing.T) {
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
		ctx     context.Context
		request *istio.LoadSEKRequest
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantResp *istio.LoadSEKResponse
		wantErr  bool
	}{
		{
			name: "OK",
			fields: fields{
				keyId:     testKid,
				keyLabel:  testLabel,
				config:    testConfig,
				ctx:       testCtx,
				encryptor: testEncryptor,
				decryptor: nil,
				createKey: false,
			},
			args: args{
				ctx: context.Background(),
				request: &istio.LoadSEKRequest{
					EncryptedDekBlob: testWrappedDEK,
					EncryptedSekBlob: testWrappedSEK,
				},
			},
			wantResp: nil,
			wantErr:  false,
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
			gotResp, err := p.LoadSEK(tt.args.ctx, tt.args.request)
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

func setupSoftHSMTestCase(t testing.TB) func(t testing.TB) {
	testuuid, err := uuid.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	testKid, err = testuuid.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	testLabel = []byte(t.Name())

	if os.Getenv("P11_LIBRARY") == "" {
		t.Skip("No P11_LIBRARY provided, skipping")
	}
	// Allow the MasterKey to be created if missing to be created

	gen := &gose.AuthenticatedEncryptionKeyGenerator{}
	var taead gose.AuthenticatedEncryptionKey

	taead, testAESKeyJWK, err = gen.Generate(jose.AlgA256GCM, keyOps)
	if testAESKeyJWKString, err = gose.JwkToString(testAESKeyJWK); err != nil {
		t.Fatal(err)
	}
	testPlainMessage = []byte("Hello World, I'm a DEK, Secret, or something sensitive")
	testEncryptor = gose.NewJweDirectEncryptorImpl(taead)
	testEncryptedBlob, err = gose.NewJweDirectEncryptorImpl(taead).Encrypt(testPlainMessage, nil)
	// Create the default key just so we can do some practical encrypt decrypting without having to mock..
	if testWrappedDEK, err = generateDEK(testCtx, testEncryptor, istio.KeyKind_AES, defaultDEKSize); err != nil {
		t.Fatal(err)
	}


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
