/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"golang.org/x/sync/errgroup"
	"os"
	"path/filepath"
	"time"
)

var loop bool
var maxLoops int
var loopTime, timeout time.Duration
var defaultAAD = []byte("this is clear but can't change...")
var fakeCSR = &x509.CertificateRequest{
	Raw:                      nil,
	RawTBSCertificateRequest: nil,
	RawSubjectPublicKeyInfo:  nil,
	RawSubject:               nil,
	Version:                  0,
	Signature:                nil,
	SignatureAlgorithm:       0,
	PublicKeyAlgorithm:       0,
	PublicKey:                nil,
	Subject:                  pkix.Name{
		Country:            nil,
		Organization:       nil,
		OrganizationalUnit: nil,
		Locality:           nil,
		Province:           nil,
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "",
		CommonName:         "",
		Names:              nil,
		ExtraNames:         nil,
	},
	Attributes:               nil,
	Extensions:               nil,
	ExtraExtensions:          nil,
	DNSNames:                 nil,
	EmailAddresses:           nil,
	IPAddresses:              nil,
	URIs:                     nil,
}
var fakeCSRBytes []byte

const dummyCaCert = "-----BEGIN CERTIFICATE-----\n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\n4uSkCQ==\n-----END CERTIFICATE-----\n"

func init() {
	fakeCSRBytes, _ = x509.CreateCertificateRequest(rand.Reader, fakeCSR, nil)
}

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test connectivety to the socket for some encrypt/decrypt",

	RunE: func(cmd *cobra.Command, args []string) error {
		time.Sleep(2 * time.Second)

		g := &errgroup.Group{}
		if loop {
			g.Go(loopTestRun)
		} else {
			g.Go(runTest)
		}
		return g.Wait()
	},
}

func loopTestRun() error {
	count := 0
	for {
		logrus.Info("Running Tests")
		_ = runTest()
		time.Sleep(10 * time.Second)
		count++
		if count > maxLoops {
			break
		}
	}
	return nil
}

func runTest() error {
	// Run Istio e2e tests against the socket

	ictx, icancel, ic, err := istio.GetClientSocket(socketPath, timeout)
	defer icancel()
	if err != nil {
		logrus.Fatal(err)
		return err
	}

	// Generate a random UUID for request
	var kekUuid uuid.UUID
	var kekKid []byte
	kekUuid, err = uuid.NewRandom()
	if err != nil {
		return err
	}
	kekKid, err = kekUuid.MarshalText()
	if err != nil {
		return err
	}

	/*
		GenerateDEK
	*/
	logrus.Info("Test 1 GenerateKEK 256 AES")
	var genKEKResp *istio.GenerateKEKResponse
	genKEKResp, err = ic.GenerateKEK(ictx, &istio.GenerateKEKRequest{
		KekKid: kekKid,
	})
	if err != nil {
		logrus.Errorf("Test 1 Failed: %v", err)
		return err
	}
	logrus.Infof("Test 1 Returned KEK KID: %s", string(genKEKResp.KekKid))
	/*
		GenerateDEK
	*/
	logrus.Info("Test 2 GenerateDEK 256 AES")
	var genDEKResp *istio.GenerateDEKResponse
	if genDEKResp, err = ic.GenerateDEK(ictx, &istio.GenerateDEKRequest{

		KekKid: genKEKResp.KekKid,
	}); err != nil {
		logrus.Fatal(err)

		return err
	}

	logrus.Infof("Test 2 Returned EncryptedDekBlob: %s", genDEKResp.EncryptedDekBlob)

	/*
		GenerateSKey
	*/

	logrus.Info("Test 3 GenerateSKey 4096 RSA")
	var genSKeyResp *istio.GenerateSKeyResponse
	if genSKeyResp, err = ic.GenerateSKey(ictx, &istio.GenerateSKeyRequest{
		Size:             4096,
		Kind:             istio.KeyKind_RSA,
		KekKid:           genKEKResp.KekKid,
		EncryptedDekBlob: genDEKResp.EncryptedDekBlob,
	}); err != nil {
		logrus.Fatal(err)
		return err
	}
	logrus.Infof("Test 3 Returned WrappedSKEY: %s", genSKeyResp.EncryptedSkeyBlob)

	/*
		LoadSKEY
	*/
	logrus.Info("Test 4 LoadSKEY 4096 RSA")
	var loadSKEYResp *istio.LoadSKeyResponse
	if loadSKEYResp, err = ic.LoadSKey(ictx, &istio.LoadSKeyRequest{

		KekKid:            genKEKResp.KekKid,
		EncryptedDekBlob:  genDEKResp.EncryptedDekBlob,
		EncryptedSkeyBlob: genSKeyResp.EncryptedSkeyBlob,
	}); err != nil {
		logrus.Fatal(err)
		return err
	}
	var out string
	if debug {
		out = string(loadSKEYResp.PlaintextSkey)
	} else {
		out = "Success"
	}
	// Load the PEM and use it...
	var skey *rsa.PrivateKey
	var b *pem.Block
	b, _ = pem.Decode(loadSKEYResp.PlaintextSkey)
	if skey, err = x509.ParsePKCS1PrivateKey(b.Bytes); err != nil {
		logrus.Fatal(err)

		return err
	}
	logrus.Infof("Test 4 Returned LoadedSKey in PEM Format: %v", out)
	skey.Public()

	/*
		AuthenticatedEncrypt
	*/
	logrus.Info("Test 5 AuthenticatedEncrypt ")
	var aeResp *istio.AuthenticatedEncryptResponse
	if aeResp, err = ic.AuthenticatedEncrypt(ictx, &istio.AuthenticatedEncryptRequest{
		KekKid: genKEKResp.KekKid,
		EncryptedDekBlob: genDEKResp.EncryptedDekBlob,
		Plaintext: []byte("Hello World"),
		Aad: defaultAAD,
	}); err != nil {
		logrus.Fatal(err)
		return err
	}

	logrus.Infof("Test 5 Returned AuthenticatedEncrypt: %s", aeResp.Ciphertext)
	/*
		AuthenticatedEncrypt
	*/
	logrus.Info("Test 6 AuthenticatedDecrypt ")
	var adResp *istio.AuthenticatedDecryptResponse
	if adResp, err = ic.AuthenticatedDecrypt(ictx, &istio.AuthenticatedDecryptRequest{
		KekKid:       genKEKResp.KekKid,
		EncryptedDekBlob:  genDEKResp.EncryptedDekBlob,
		Ciphertext:   aeResp.Ciphertext,
		Aad:          defaultAAD,
	}); err != nil {
		logrus.Fatal(err)
		return err
	}

	logrus.Infof("Test 6 Returned AuthenticatedDecrypt: %s", adResp.Plaintext)


	logrus.Info("Test 7 ImportCACert ")
	

	var icResp *istio.ImportCACertResponse
	if icResp, err = ic.ImportCACert(ictx, &istio.ImportCACertRequest{
		KekKid:       genKEKResp.KekKid,
		CaCertBlob:  []byte(dummyCaCert),
	}); err != nil {
		logrus.Fatal(err)
		return err
	}

	logrus.Infof("Test 7 Returned ImportCACert: %v", icResp.Success)


	



	/*
		AuthenticatedDecrypt
	*/

	return nil
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", ".sock"), "Unix Socket")
	testCmd.Flags().BoolVar(&loop, "loop", false, "Should we run the test in a loop?")
	testCmd.Flags().DurationVar(&loopTime, "loop-sleep", 10, "How many seconds to sleep between test runs ")
	testCmd.Flags().IntVar(&maxLoops, "max-loops", 100, "How many seconds to sleep between test runs ")

	testCmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "Timeout Duration")
	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// testCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// testCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
