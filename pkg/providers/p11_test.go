package providers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/jose"
	"github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	v1 "github.com/ThalesGroup/k8s-kms-plugin/apis/kms/v1"
	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	k8s "github.com/ThalesGroup/k8s-kms-plugin/apis/k8s/v1beta1"
)

var (
	testAESKeyJWK       jose.Jwk
	testAESKeyJWKString string
	testConfig          *crypto11.Config
	testCtx             *crypto11.Context
	testEncryptedBlob   string
	testCert            *x509.Certificate
	testCertPem         []byte
	testDecryptor       map[string]gose.JweDecryptor
	testEncryptor       map[string]gose.JweEncryptor
	testKid             []byte
	testCid             []byte
	testPlainMessage    []byte
	testWrappedDEK      []byte
	testWrappedSKey     []byte
	testAlgorithm       jose.Alg
)

type testCaseFields struct {
	keyId      []byte
	keyLabel   []byte
	config     *crypto11.Config
	ctx        *crypto11.Context
	encryptors map[string]gose.JweEncryptor
	decryptors map[string]gose.JweDecryptor
	createKey  bool
	algorithm  jose.Alg
}

type testCaseArgs struct {
	ctx context.Context
	req *k8s.EncryptRequest
}

type testCase struct {
	name     string
	fields   testCaseFields
	args     testCaseArgs
	wantResp *k8s.EncryptResponse
	wantErr  bool
}

var (
	test1 = testCase{
		name: "Happy Path - create default",
		fields: testCaseFields{
			config:   testConfig,
			ctx:      testCtx,
			keyId:    []byte("afdjaklfjdaskl"),
			keyLabel: []byte(defaultKEKlabel),

			encryptors: testEncryptor,
			decryptors: testDecryptor,
			createKey:  true,
		},
		args: testCaseArgs{
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
	}

	test2 = testCase{
		name: "Test Encrypt then Hmac with AES CBC + SHA 256",
		fields: testCaseFields{
			keyId:      []byte("123456789"),
			keyLabel:   []byte("aes0"),
			config:     testConfig,
			ctx:        testCtx,
			encryptors: testEncryptor,
			decryptors: testDecryptor,
			createKey:  false,
			algorithm:  testAlgorithm,
		},
		args: testCaseArgs{
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
	}
)

func makeTestCases(t testing.TB) (tests []testCase, td func(testing.TB)) {
	tpm := os.Getenv("P11_MODE") == "tpm"
	if tpm {
		setupTpm2Pkcs11TestCase(t)
		tests = []testCase{
			{
				name: "Test Encrypt then Hmac with AES CBC + SHA 256",
				fields: testCaseFields{
					keyId:      testKid,
					keyLabel:   []byte("aes0"),
					config:     testConfig,
					ctx:        testCtx,
					encryptors: testEncryptor,
					decryptors: testDecryptor,
					createKey:  false,
					algorithm:  testAlgorithm,
				},
				args: testCaseArgs{
					ctx: context.Background(),
					req: &k8s.EncryptRequest{
						Version: "1",
						Plain:   []byte("I only wish that ordinary people had an unlimited capacity for doing harm; then they might have an unlimited power for doing good."),
						KeyId:   string(testKid),
					},
				},
				wantResp: &k8s.EncryptResponse{

					Cipher: []byte(testEncryptedBlob),
				},
				wantErr: false,
			},
		}
	} else {
		td = setupSoftHSMTestCase(t)
		tests = []testCase{
			{
				name: "Happy Path - create default",
				fields: testCaseFields{
					config:   testConfig,
					ctx:      testCtx,
					keyId:    []byte("afdjaklfjdaskl"),
					keyLabel: []byte(defaultKEKlabel),

					encryptors: testEncryptor,
					decryptors: testDecryptor,
					createKey:  true,
				},
				args: testCaseArgs{
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
	}

	return tests, td
}

func TestP11_Encrypt(t *testing.T) {
	var tests []testCase
	var td func(testing.TB)
	if tests, td = makeTestCases(t); td != nil {
		defer td(t)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &P11{
				config:     tt.fields.config,
				ctx:        tt.fields.ctx,
				encryptors: tt.fields.encryptors,
				decryptors: tt.fields.decryptors,
				createKey:  tt.fields.createKey,
				algorithm:  tt.fields.algorithm,
			}
			gotResp, err := p.Encrypt(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// TODO handle the keyID for the decrypt request too
			var gotClearResp *k8s.DecryptResponse
			if gotClearResp, err = p.Decrypt(context.Background(), &k8s.DecryptRequest{
				Cipher:  gotResp.Cipher,
				Version: "1",
				KeyId:   string(tt.fields.keyId),
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
			p := &P11{
				config:     tt.fields.config,
				ctx:        tt.fields.ctx,
				encryptors: tt.fields.encryptors,
				decryptors: tt.fields.decryptors,
				createKey:  tt.fields.createKey,
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
			p := &P11{
				config:     tt.fields.config,
				ctx:        tt.fields.ctx,
				encryptors: tt.fields.encryptors,
				decryptors: tt.fields.decryptors,
				createKey:  tt.fields.createKey,
			}
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

func TestP11_Version(t *testing.T) {
	p := &P11{}

	versionResp, versionErr := p.Version(context.Background(), &v1.VersionRequest{})

	require.NoError(t, versionErr)

	const expectedVersion = "v1beta1"

	require.Equal(t, expectedVersion, versionResp.Version)

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
			p := &P11{
				kid:        tt.fields.kid,
				cid:        tt.fields.cid,
				config:     tt.fields.config,
				ctx:        tt.fields.ctx,
				encryptors: tt.fields.encryptors,
				decryptors: tt.fields.decryptors,
				createKey:  tt.fields.createKey,
			}
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
			p := &P11{
				config:     tt.fields.config,
				ctx:        tt.fields.ctx,
				encryptors: tt.fields.encryptors,
				decryptors: tt.fields.decryptors,
				createKey:  tt.fields.createKey,
			}
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

func setupTpm2Pkcs11TestCase(t testing.TB) {
	var err error
	// the lib pkcs11 for tpm2 does not support hte C_GenerateKey function
	// You must provide the key label to retrieve them
	secretKeyLabel := os.Getenv("PKCS11_SECRET_KEY_LABEL")
	hmacKeyLabel := os.Getenv("PKCS11_HMAC_KEY_LABEL")
	testPlainMessage = []byte("I only wish that ordinary people had an unlimited capacity for doing harm; then they might have an unlimited power for doing good.")
	testAlgorithm = jose.AlgA256CBC

	secretKey, err := testCtx.FindKey(nil, []byte(secretKeyLabel))
	require.NoError(t, err)

	att, err := testCtx.GetAttribute(secretKey, crypto11.CkaId)
	testKid = att.Value

	iv := make([]byte, secretKey.Cipher.BlockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	hmacKey, err := testCtx.FindKey(nil, []byte(hmacKeyLabel))
	require.NoError(t, err)
	hash, err := hmacKey.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
	require.NoError(t, err)
	shaKey := gose.NewHmacShaCryptor("testHmacKid", hash)

	blockModeEncrypter, err := secretKey.NewCBCEncrypterCloser(iv)
	require.NoError(t, err)
	cbcKeyEnc := gose.NewAesCbcCryptor(blockModeEncrypter, string(testKid), testAlgorithm)
	testKid = []byte(cbcKeyEnc.Kid())

	blockModeDecrypter, err := secretKey.NewCBCDecrypterCloser(iv)
	require.NoError(t, err)
	cbcKeyDec := gose.NewAesCbcCryptor(blockModeDecrypter, string(testKid), testAlgorithm)

	testEncryptor = map[string]gose.JweEncryptor{}
	testEncryptor[secretKeyLabel] = gose.NewJweDirectEncryptorBlock(cbcKeyEnc, shaKey, iv)
	testEncryptedBlob, err = testEncryptor[secretKeyLabel].Encrypt(testPlainMessage, nil)

	testDecryptor = map[string]gose.JweDecryptor{}
	testDecryptor[secretKeyLabel] = gose.NewJweDirectDecryptorBlock(cbcKeyDec, shaKey)

}

func setupSoftHSMTestCase(t testing.TB) func(t testing.TB) {
	testKuuid, err := uuid.NewRandom()
	var testCuuid uuid.UUID
	if err != nil {
		t.Fatal(err)
	}
	testKid, err = testKuuid.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	testCuuid, err = uuid.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	testCid, err = testCuuid.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("P11_LIBRARY") == "" {
		t.Skip("No P11_LIBRARY provided, skipping")
	}
	// Allow the MasterKey to be created if missing to be created
	gen := &gose.AuthenticatedEncryptionKeyGenerator{}
	var taead gose.AeadEncryptionKey

	taead, testAESKeyJWK, err = gen.Generate(jose.AlgA256GCM, kekKeyOps)
	if testAESKeyJWKString, err = gose.JwkToString(testAESKeyJWK); err != nil {
		t.Fatal(err)
	}
	testPlainMessage = []byte("Hello World, I'm a DEK, Secret, or something sensitive")
	testEncryptor = map[string]gose.JweEncryptor{}
	testEncryptor[string(testKid)] = gose.NewJweDirectEncryptorAead(taead, false)
	testDecryptor = map[string]gose.JweDecryptor{}
	testDecryptor[string(testKid)] = gose.NewJweDirectDecryptorAeadImpl([]gose.AeadEncryptionKey{taead})
	testEncryptedBlob, err = gose.NewJweDirectEncryptorAead(taead, false).Encrypt(testPlainMessage, nil)
	// Create the default key just so we can do some practical encrypt decrypting without having to mock..
	if _, err = generateKEK(testCtx, testKid, []byte(defaultKEKlabel), jose.AlgA256GCM); err != nil {
		t.Fatal(err)
	}
	if testWrappedDEK, err = generateDEK(testCtx, testEncryptor[string(testKid)]); err != nil {
		t.Fatal(err)
	}
	templateCA := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   "Test CA",
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
	var rng io.Reader
	if rng, err = testCtx.NewRandomReader(); err != nil {
		t.Fatal(err)
	}
	var k crypto.Signer
	if k, err = testCtx.FindKeyPair(testKid, []byte(defaultKEKlabel)); err != nil {
		t.Fatal(err)
	}
	if k, err = rsa.GenerateKey(rng, 2048); err != nil {
		t.Fatal(err)
	}
	var caBytes []byte
	if caBytes, err = x509.CreateCertificate(rng, templateCA, templateCA, k.Public(), k); err != nil {
		t.Fatal(err)
	}
	testCertPem = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	testCert = templateCA

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
