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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/jose"
	"github.com/ThalesGroup/k8s-kms-plugin/pkg/providers"

	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	k8skmsv2 "k8s.io/kms/apis/v2"
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

// testing value for the kek CKA_LABEL
var defaultKEKlabel = []byte("k8s-kms-plugin-kek")

// testing value
var kekKeyOps = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}

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
	req *k8skmsv2.EncryptRequest
}

type testCase struct {
	name     string
	fields   testCaseFields
	args     testCaseArgs
	wantResp *k8skmsv2.EncryptResponse
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
			req: &k8skmsv2.EncryptRequest{
				//Uid: "...", // TODO: handle this
				Plaintext: testPlainMessage,
			},
		},
		wantResp: &k8skmsv2.EncryptResponse{
			Ciphertext: []byte(testEncryptedBlob),
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
			req: &k8skmsv2.EncryptRequest{
				//Uid: "...", // TODO: handle this
				Plaintext: testPlainMessage,
			},
		},
		wantResp: &k8skmsv2.EncryptResponse{
			Ciphertext: []byte(testEncryptedBlob),
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
					req: &k8skmsv2.EncryptRequest{
						//Uid: "...", // TODO: handle this
						Plaintext: []byte("I only wish that ordinary people had an unlimited capacity for doing harm; then they might have an unlimited power for doing good."),
					},
				},
				wantResp: &k8skmsv2.EncryptResponse{

					Ciphertext: []byte(testEncryptedBlob),
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
					req: &k8skmsv2.EncryptRequest{
						//Uid: "...", // TODO: handle this
						Plaintext: testPlainMessage,
					},
				},
				wantResp: &k8skmsv2.EncryptResponse{
					Ciphertext: []byte(testEncryptedBlob),
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
			p, err := providers.NewP11(
				tt.fields.config,
				tt.fields.createKey,
				"", // kekkeyid
				"", // k8sKekLabel
				"", // hmacKeyLabel
				"", // hmacCkaId
				tt.fields.algorithm,
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

			gotResp, err := p.Encrypt(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// TODO handle the keyID for the decrypt request too
			var gotClearResp *k8skmsv2.DecryptResponse
			if gotClearResp, err = p.Decrypt(context.Background(), &k8skmsv2.DecryptRequest{
				Ciphertext: gotResp.GetCiphertext(),
				//Uid: "...", // TODO: handle this
				KeyId: string(tt.fields.keyId),
			}); err != nil {
				t.Errorf("Unable to decrypt the payload... danger!!!")
				return
			}
			if string(gotClearResp.Plaintext) != string(testPlainMessage) {
				t.Errorf("bad decrypt... something really wrong!!!")
				return
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
	if err != nil {
		logrus.WithError(err).Errorf("setupTpm2Pkcs11TestCase: cannot get the CKA_ID attribute for the secret key %v", secretKeyLabel)
		return
	}
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
	if _, err = providers.GenerateKEK(testCtx, testKid, []byte(defaultKEKlabel), jose.AlgA256GCM); err != nil {
		t.Fatal(err)
	}
	if testWrappedDEK, err = providers.GenerateDEK(testCtx, testEncryptor[string(testKid)]); err != nil {
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

// randomSerial returns a random big.Int suitable for use as an X.509v3 certificate
// serial number.
func randomSerial() (serial *big.Int) {
	serial, _ = rand.Int(rand.Reader, big.NewInt(20000))
	return
}
