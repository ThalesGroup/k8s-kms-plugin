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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"golang.org/x/sync/errgroup"
	"hash"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

/* Dummy CA */
const dummyCaCert = "-----BEGIN CERTIFICATE-----\n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\n4uSkCQ==\n-----END CERTIFICATE-----\n"
const dummyCaBadCert = "-----BEGIN CERTIFICATE-----\n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\nPJhSoqY=\n-----END CERTIFICATE-----"
const dummyCaPrivKey = "-----BEGIN PRIVATE KEY-----\n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\n-----END PRIVATE KEY-----"

var loop bool
var maxLoops int
var loopTime, timeout time.Duration

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

func hashCsrTemplate(hashF hash.Hash, csrTemplate *x509.CertificateRequest) (digest []byte, err error) {

	hashF.Reset()

	_, err = hashF.Write([]byte(csrTemplate.Subject.String()))
	if nil != err {
		return
	}

	if nil != csrTemplate.DNSNames {
		for i := 0; i < len(csrTemplate.DNSNames); i++ {
			_, err = hashF.Write([]byte(csrTemplate.DNSNames[i]))
			if nil != err {
				return
			}
		}
	}

	if nil != csrTemplate.EmailAddresses {
		for i := 0; i < len(csrTemplate.EmailAddresses); i++ {
			_, err = hashF.Write([]byte(csrTemplate.EmailAddresses[i]))
			if nil != err {
				return
			}
		}
	}

	if nil != csrTemplate.IPAddresses {
		for i := 0; i < len(csrTemplate.IPAddresses); i++ {
			_, err = hashF.Write([]byte(csrTemplate.IPAddresses[i]))
			if nil != err {
				return
			}
		}
	}

	digest = hashF.Sum(digest)

    return
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


	// Generate a dummy istiod intermediate CA CSR from this
	var csrTemplate = &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"istio"},
		},
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA512WithRSA,
		DNSNames:           []string{"test.example.com"},
		EmailAddresses:     []string{"gopher@golang.org"},
		IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4()},
	}

	var istioIntermediateCaCSR []byte
	if istioIntermediateCaCSR, err = x509.CreateCertificateRequest(rand.Reader, csrTemplate, skey); nil != err {
		logrus.Fatal(err)
		return err
	}

	/*
		AuthenticatedEncrypt
	*/

	var aadHashOfSelectedCsrTemplateFields []byte
	aadHashOfSelectedCsrTemplateFields, err = hashCsrTemplate(sha256.New(), csrTemplate)
	if nil != err {
		logrus.Fatal(err)
		return err
	}

	logrus.Info("Test 5 AuthenticatedEncrypt ")
	var aeResp *istio.AuthenticatedEncryptResponse
	if aeResp, err = ic.AuthenticatedEncrypt(ictx, &istio.AuthenticatedEncryptRequest{
		KekKid:           genKEKResp.KekKid,
		EncryptedDekBlob: genDEKResp.EncryptedDekBlob,
		Plaintext:        istioIntermediateCaCSR,
		Aad:              aadHashOfSelectedCsrTemplateFields,
	}); err != nil {
		logrus.Fatal(err)
		return err
	}

	logrus.Infof("Test 5 Returned AuthenticatedEncrypt: %s", aeResp.Ciphertext)
	/*
		AuthenticatedDecrypt
	*/
	logrus.Info("Test 6 AuthenticatedDecrypt ")
	var adResp *istio.AuthenticatedDecryptResponse
	if adResp, err = ic.AuthenticatedDecrypt(ictx, &istio.AuthenticatedDecryptRequest{
		KekKid:       genKEKResp.KekKid,
		EncryptedDekBlob:  genDEKResp.EncryptedDekBlob,
		Ciphertext:   aeResp.Ciphertext,
		Aad:          aadHashOfSelectedCsrTemplateFields,
	}); err != nil {
		logrus.Fatal(err)
		return err
	}
	logrus.Debugf("istioIntermediateCaCSR: %v", string(adResp.Plaintext))

	logrus.Infof("Test 6 Returned AuthenticatedDecrypt (b64): %s", base64.URLEncoding.EncodeToString(adResp.Plaintext))


    /*
     * ================================
     *
     * Signing of CSR using upstream CA
     *
     * ================================
    */

    var reloadedCsr *x509.CertificateRequest
    reloadedCsr, err = x509.ParseCertificateRequest(adResp.Plaintext)
    if nil != err {
    	logrus.Fatal(err)
    	return err
	}

	var pemCaCertBlock *pem.Block
    pemCaCertBlock, _ = pem.Decode([]byte(dummyCaCert))
    var parsedRootCaCert *x509.Certificate
    parsedRootCaCert, err = x509.ParseCertificate(pemCaCertBlock.Bytes)
    if nil != err {
    	logrus.Fatal(err)
    	return err
	}

	var pemBadCaCertBlock *pem.Block
	pemBadCaCertBlock, _ = pem.Decode([]byte(dummyCaBadCert))

	var pemKeyBlock *pem.Block
    pemKeyBlock, _ = pem.Decode([]byte(dummyCaPrivKey))
    var parsedCaPrivKey *rsa.PrivateKey
	parsedCaPrivKey, err = x509.ParsePKCS1PrivateKey(pemKeyBlock.Bytes)
    if nil != err {
    	logrus.Fatal(err)
    	return err
	}

	// Sanity check
	if nil != reloadedCsr.CheckSignature() {
		logrus.Fatal(err)
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.Fatalf("Failed to generate serial number: %v", err)
	}

	var childTemplate = &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: reloadedCsr.Subject.Organization,
			CommonName: reloadedCsr.Subject.CommonName,
		},

		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		PublicKeyAlgorithm: x509.RSA,

		SubjectKeyId: []byte{1, 2, 3, 4},

		IsCA:                  true,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 1),

		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
	}
	signedCert, signCertErr := x509.CreateCertificate(rand.Reader, childTemplate, parsedRootCaCert, reloadedCsr.PublicKey, parsedCaPrivKey)
	if nil != signCertErr {
		logrus.Fatal(signCertErr)
		return signCertErr
	}

	var loadedSignedCert = &x509.Certificate{}
	loadedSignedCert, err = x509.ParseCertificate(signedCert)
	if nil != err {
		logrus.Fatal(err)
		return err
	}

	// Sanity check
	certPool := x509.NewCertPool()
	certPool.AddCert(parsedRootCaCert)
	_, err = loadedSignedCert.Verify(x509.VerifyOptions{Roots: certPool})
	if nil != err {
		logrus.Fatal(err)
		return err
	}

	/*
	 * ====================================
	 *
	 * End signing of CSR using upstream CA
	 *
	 * ====================================
	 */


	/*
	   VerifyCertChain - take the decrypted CSR, sign it using the dummy (upstream CA), then hand over to verify the chain
	*/
	logrus.Info("Test 7 VerifyCertChain")
    chain := make([][]byte, 0)
	chain = append(chain, signedCert)
	chain = append(chain, pemCaCertBlock.Bytes)

	var verifyCertChainReq = &istio.VerifyCertChainRequest{
		Certificates: chain,
	}
	var verifyCertChainResp = &istio.VerifyCertChainResponse{}
	if verifyCertChainResp, err = ic.VerifyCertChain(ictx, verifyCertChainReq); nil != err {
		logrus.Fatal(err)
		return err
	}

	if !verifyCertChainResp.SuccessfulVerification {
		logrus.Fatal("VerifyCertChain returned false")
		return fmt.Errorf("VerifyCertChain returned false")
	}
	logrus.Printf("VerifyCertChain succeeded")





	// Negative test that verify fails with the bad CA cert
	logrus.Info("Test 8 Negative VerifyCertChain")
	badChain := make([][]byte, 0)
	badChain = append(badChain, signedCert)
	badChain = append(badChain, pemBadCaCertBlock.Bytes)

	var verifyCertBadChainReq = &istio.VerifyCertChainRequest{
		Certificates: badChain,
	}
	var verifyCertBadChainResp = &istio.VerifyCertChainResponse{}
	if verifyCertBadChainResp, err = ic.VerifyCertChain(ictx, verifyCertBadChainReq); nil == err {
		logrus.Fatal("VerifyCertChain returned true")
		return fmt.Errorf("VerifyCertChain returned true")
	}

	logrus.Printf("VerifyCertBadChain succeeded (failed)")

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
