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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/kms/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"os"
	"path/filepath"
	"time"
)

var loop bool
var maxLoops int
var loopTime, timeout time.Duration

const (
	testDekName1 = "test-kms-dek-1"
	testDekName2 = "test-kms-dek-2"
	testCakName1 = "test-kms-cak-1"
	testCakName2 = "test-kms-cak-2"
)

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
	// Run kms e2e tests against the socket

	ictx, icancel, ic, err := kms.GetClientSocket(socketPath, timeout)
	defer icancel()
	if err != nil {
		logrus.Fatal(err)
		return err
	}
	//kctx, kcancel, kc, err := k8s.GetClientSocket(socketPath, timeout)
	//defer kcancel()
	//if err != nil {
	//	logrus.Fatal(err)
	//	return err
	//}

	/*
		HealthCheck
	*/
	logrus.Info("------------------------------------------------------------")
	logrus.Info("Test 1 HealthCheck - Handler(s) should always stay up...")
	logrus.Info("------------------------------------------------------------")

	/*
		GetPublicKey
	*/
	logrus.Info("------------------------------------------------------------")
	logrus.Info("Test 2 GetPublicKey - Get the Public Key for the Root CA")
	var pubKey *kms.PublicKey
	if pubKey, err = ic.GetPublicKey(ictx, &kms.GetPublicKeyRequest{
		IncludeBundle: false,
	}); err != nil {
		return err
	}
	if pubKey == nil {
		err = status.Error(codes.Internal, "pubic key unavailable... did you bootstrap the PKCS11 device?")
		return err
	}
	logrus.Infof("Public Key : %s", pubKey.Algorithm.String())
	/*
		CreateCryptoKey ENCRYPT_DECRYPT
	*/
	logrus.Info("------------------------------------------------------------")
	logrus.Info("Test 3 CreateCryptoKey - Purpose ENCRYPT_DECRYPT")

	var dek *kms.CryptoKey

	if dek, err = ic.CreateCryptoKey(ictx, &kms.CreateCryptoKeyRequest{
		CryptoKeyId: testDekName1,
		CryptoKey: &kms.CryptoKey{
			Name:       testDekName1,
			Purpose:    kms.CryptoKey_ENCRYPT_DECRYPT,
			CreateTime: timestamppb.New(time.Now()),
		},
	}); err != nil {
		return err
	}

	logrus.Infof("Created CryptoKey DEK : %s ", testDekName1)
	logrus.Info("------------------------------------------------------------")

	/*
		CreateCryptoKey -
	*/
	logrus.Info("------------------------------------------------------------")
	logrus.Info("Test 4 Encrypt and Decrypt - Simple")
	var encryptResp *kms.EncryptResponse
	if encryptResp, err = ic.Encrypt(ictx, &kms.EncryptRequest{
		Name:                        dek.Name,
		Plaintext:                   []byte("Hello World"),
		AdditionalAuthenticatedData: []byte("some aad"),
	}); err != nil {
		return err
	}
	logrus.Infof("Encrypted : %s", string(encryptResp.Ciphertext))
	var decryptResp *kms.DecryptResponse
	if decryptResp, err = ic.Decrypt(ictx, &kms.DecryptRequest{
		Name:                        dek.Name,
		Ciphertext:                  encryptResp.Ciphertext,
		AdditionalAuthenticatedData: []byte("some aad"),
	}); err != nil {
		return err
	}
	logrus.Infof("Decrypted : %s", string(decryptResp.Plaintext))
	logrus.Info("------------------------------------------------------------")

	/*
		CreateCryptoKey -
	*/
	logrus.Info("------------------------------------------------------------")
	logrus.Info("Test 5 CreateCryptoKey - Purpose ASYMMETRIC_SIGN")
	var cak *kms.CryptoKey
	if cak, err = ic.CreateCryptoKey(ictx, &kms.CreateCryptoKeyRequest{
		CryptoKeyId: testDekName1,
		CryptoKey: &kms.CryptoKey{
			Name:       "AEAD1",
			Purpose:    kms.CryptoKey_ASYMMETRIC_SIGN,
			CreateTime: timestamppb.New(time.Now()),
		},
	}); err != nil {
		return err
	}
	logrus.Infof("Generated CryptoKey : %s", cak.Name)
	logrus.Infof("Created CAK : %s ", testCakName1)
	logrus.Info("------------------------------------------------------------")

	//var genKEKResp *kms.GenerateKEKResponse
	//genKEKResp, err = ic.GenerateKEK(ictx, &kms.GenerateKEKRequest{
	//	KekKid: kekKid,
	//})
	//if err != nil {
	//	logrus.Errorf("Test 1 Failed: %v", err)
	//	return err
	//}
	//logrus.Infof("Test 1 Returned KEK ID: %s", string(genKEKResp.KekKid))
	///*
	//	GenerateDEK
	//*/
	//logrus.Info("Test 2 GenerateDEK 256 AES")
	//var genDEKResp *kms.GenerateDEKResponse
	//if genDEKResp, err = ic.GenerateDEK(ictx, &kms.GenerateDEKRequest{
	//	Size:   256,
	//	Kind:   kms.KeyKind_AES,
	//	KekKid: genKEKResp.KekKid,
	//}); err != nil {
	//	logrus.Fatal(err)
	//
	//	return err
	//}
	//
	//logrus.Infof("Test 2 Returned WrappedDEK: %s", genDEKResp.EncryptedDekBlob)
	//
	///*
	//	GenerateSEK
	//*/
	//
	//logrus.Info("Test 3 GenerateSEK 4096 RSA")
	//var genSEKResp *kms.GenerateSEKResponse
	//if genSEKResp, err = ic.GenerateSEK(ictx, &kms.GenerateSEKRequest{
	//	Size:             4096,
	//	Kind:             kms.KeyKind_RSA,
	//	KekKid:           genKEKResp.KekKid,
	//	EncryptedDekBlob: genDEKResp.EncryptedDekBlob,
	//}); err != nil {
	//	logrus.Fatal(err)
	//	return err
	//}
	//logrus.Infof("Test 3 Returned WrappedSEK: %s", genSEKResp.EncryptedSekBlob)
	//
	///*
	//	LoadSEK
	//*/
	//logrus.Info("Test 4 LoadSEK 4096 RSA")
	//var loadSEKResp *kms.LoadSEKResponse
	//if loadSEKResp, err = ic.LoadSEK(ictx, &kms.LoadSEKRequest{
	//
	//	KekKid:           genKEKResp.KekKid,
	//	EncryptedDekBlob: genDEKResp.EncryptedDekBlob,
	//	EncryptedSekBlob: genSEKResp.EncryptedSekBlob,
	//}); err != nil {
	//	logrus.Fatal(err)
	//	return err
	//}
	//var out string
	//if debug {
	//	out = string(loadSEKResp.ClearSek)
	//} else {
	//	out = "Success"
	//}
	//// Load the PEM and use it...
	//var sek *rsa.PrivateKey
	//var b *pem.Block
	//b, _ = pem.Decode(loadSEKResp.ClearSek)
	//if sek, err = x509.ParsePKCS1PrivateKey(b.Bytes); err != nil {
	//	logrus.Fatal(err)
	//
	//	return err
	//}
	//logrus.Infof("Test 4 Returned LoadedSEK in PEM Format: %v", out)
	///*
	//	GenerateCAK
	//*/
	//logrus.Info("Test 5 GenerateCAK 4096 RSA")
	//var genCAKResp *kms.GenerateCAKResponse
	//if genCAKResp, err = kc.GenerateCAK(kctx, &kms.GenerateCAKRequest{
	//	Size:      4096,
	//	Kind:      kms.KeyKind_RSA,
	//	RootCaKid: cakKid,
	//}); err != nil {
	//	logrus.Fatal(err)
	//	return err
	//}
	//
	//logrus.Infof("Test 5  GenerateCAK KID Returned: %s", string(genCAKResp.RootCaKid))
	///*
	//	GenerateCA
	//*/
	//logrus.Info("Test 6 GenerateCA, Sign and Store")
	//var genCAResp *kms.GenerateCAResponse
	//if genCAResp, err = kc.GenerateCA(kctx, &kms.GenerateCARequest{
	//
	//	RootCaKid: cakKid,
	//}); err != nil {
	//	logrus.Fatal(err)
	//	return err
	//}
	//if debug {
	//	out = string(genCAResp.Cert)
	//} else {
	//	out = "Success"
	//}
	//logrus.Infof("Test 6  GenerateCA in : %s", out)
	//
	///*
	//	SignCSR
	//*/
	//logrus.Info("Test 7 SignCSR Root CA Cert")
	//var signCSRResp *kms.SignCSRResponse
	//template := &x509.CertificateRequest{
	//
	//	SignatureAlgorithm: x509.SHA512WithRSA,
	//	PublicKeyAlgorithm: x509.RSA,
	//	Subject: pkix.Name{
	//		CommonName: "Hello",
	//	},
	//	PublicKey: sek.Public(),
	//	DNSNames:  []string{"awesome.com"},
	//}
	//req := &kms.SignCSRRequest{
	//	RootCaKid: cakKid,
	//}
	//
	//if req.Csr, err = x509.CreateCertificateRequest(rand.Reader, template, sek); err != nil {
	//	return err
	//}
	//if signCSRResp, err = kc.SignCSR(kctx, req); err != nil {
	//	logrus.Fatal(err)
	//	return err
	//}
	//
	//logrus.Infof("Test 7 SignCSR Cert: %s", string(signCSRResp.Cert))
	//
	///*
	//	DestroyCA
	//*/
	//logrus.Info("Test 8 DestroyCA")
	//var destroyCAResp *kms.DestroyCAResponse
	//if destroyCAResp, err = kc.DestroyCA(kctx, &kms.DestroyCARequest{
	//	KekKid: cakKid,
	//}); err != nil {
	//	logrus.Fatal(err)
	//	return err
	//}
	//
	//logrus.Infof("Test 8 DestroyCA result : %b", destroyCAResp.Success)
	//
	///*
	//	DestroyCAK
	//*/
	//logrus.Info("Test 9 DestroyCA")
	//var destroyCAKResp *kms.DestroyCAKResponse
	//if destroyCAKResp, err = kc.DestroyCAK(kctx, &kms.DestroyCAKRequest{
	//	KekKid: cakKid,
	//}); err != nil {
	//	logrus.Fatal(err)
	//	return err
	//}
	//
	//logrus.Infof("Test 9 DestroyCAK result : %b", destroyCAKResp.Success)
	//logrus.Infof("------------------------------------------------------------")
	return err

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
