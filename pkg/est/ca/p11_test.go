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
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"os"
	"testing"
)

var testConfig *crypto11.Config
var testCtx *crypto11.Context

var testEncryptedBlob string
var testPlainMessage []byte

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
