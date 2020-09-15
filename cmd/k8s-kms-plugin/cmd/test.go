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

var loop bool
var maxLoops int
var loopTime, timeout time.Duration


const dummyCaCert = "-----BEGIN CERTIFICATE-----\nMIIGADCCA7SgAwIBAgIQAzUe9pVQo20RU9LSiRiDkDBBBgkqhkiG9w0BAQowNKAP\nMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMC\nASAwLTEQMA4GA1UEChMHQWNtZSBDbzEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNv\nbTAeFw0yMDA5MTUxMDEwNTlaFw0zMDA5MTMxMDEwNTlaMC0xEDAOBgNVBAoTB0Fj\nbWUgQ28xGTAXBgNVBAMTEHRlc3QuZXhhbXBsZS5jb20wggIiMA0GCSqGSIb3DQEB\nAQUAA4ICDwAwggIKAoICAQCuaGKyDvJ0ebW/9Kq7fltuLZhWQJb613EcHc2eV7ht\nejffCYklRJeKONhkozroxsb5y0ETvlWRiBDVBj0Zq0dyHY781N/QJZcBons0cRXV\nYNBd4nUaJ//FufzI1mbSXohpSaV1hkoQ2uTqB4B7yUWaiM1nIx1snzdXJSGhVYxy\nRhdTHMNd/z8ut+dwRojFIiU7S5NXaCc9LL9LryXy1N+VZo6sHK6NZQu27ryE7wv1\nh+bvG6TsfIsmfcv94ghX94olxY/+h38sDrX3LboKt3j8Tktg3amnwuKENYnvTOMZ\nkHkofj6k8kx+lCzJLDi2hCcq3r3ZPoT146mU5v3nwGF0zPSN3+GertuI9rmSvUy+\ngeD5QeWczUgADaALMVBTQY+wEBNhzyWa6O/l/yPErW2epFSibHIyz+97Nlen9CaF\nKBAUhRYVJIaUOCPmCK5VW4ghadF8zflUsgo5s/himfs9CWF12yAEYS1MjhyTTmAa\n0/DymJ0M8kaTuVUoQW6rrPGAzVRQEBeeVa3OJY6mPvOq0XosYGXtROSq9DMPGwcy\no9OlXhw6uD/rBPxNC8cqDZviM3QHKoN4lGatgfuSrowIU5Bi1yzgMxKdouY78OEI\nThtQTw2XxdoUy+Vr0XlQg9gAJqP0mq1O8fu7zjhua9k8Pdm6B0fxGsBa0Yz4MMQn\nIwIDAQABo4GzMIGwMA4GA1UdDwEB/wQEAwICBDAdBgNVHSUEFjAUBggrBgEFBQcD\nAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zANBgNVHQ4EBgQEAQIDBDBfBggr\nBgEFBQcBAQRTMFEwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmV4YW1wbGUuY29t\nMCoGCCsGAQUFBzAChh5odHRwOi8vY3J0LmV4YW1wbGUuY29tL2NhMS5jcnQwQQYJ\nKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglg\nhkgBZQMEAgEFAKIDAgEgA4ICAQCfFnc0Cajm48LiDw2NxSsNMCGCT/uju6KJG3O8\naXG6rEorDJs3uWCdyn6PhzyhqEdPGiBfJVJnmY9OfF8wWx3zXVAxstOp1RIrA3yI\nfIZAMoTsAYYKXH9gMda9wcPMFOFKrjbmDJKk8c3WwXth5NIeqqQPGTTh0ovHVc8Q\nHDSZo3lyBEmUDjrF2qu0VGn4m2kuxFl8lPUAu8lUR2+KLj6XStqhDd6gXCa2/quZ\nSROFRccS5bPEwJh7l1QSqhwHjS0oKU0sIGq6+VPq2TKUcf4F1zaw4dOKqhBbm+o1\nN7K49deaQH3Zb40jR7f2Rw+s86MM1ujS8tu98yRcu8+KPq1vb1fOQlG/UnOAtYd7\n8kej0ot/QYb7NxDqxNqW2vePbkUoOHV9TtRNQDV0hQooWB/GzZGWUrILDRugDwH+\nX7XNzC5ov1TbRpXkvmpBkY80oBFb9P4bCtUb2dmcdxM7KM5dnoHOQ8Fb7aSWcstE\nSOI2qbSnl2/uigjWLayWpn6k1OTszsLQTxAcezNLL6cTI+eWb3oC0KoAP458FtNH\nb/W8F2WNIxCjD9ydVU2JFPRSy1FfAQFhNMPwyIoT4AZ46G/u4gNu/AIPERfCUqdG\nQWUMsGgTs6NVDmo5YeasplU5uYyEvqPnUhZFsxNSPu/wmDiIcjrtIeEym7Dq4MiG\neOMvxQ==\n-----END CERTIFICATE-----"
const dummyBadCaCert = "-----BEGIN CERTIFICATE-----\n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\nPJhSoqY=\n-----END CERTIFICATE-----"
const dummyCaPrivKey = "-----BEGIN PRIVATE KEY-----\n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\n-----END PRIVATE KEY-----\n"

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
		KekKid: genKEKResp.KekKid,
		EncryptedDekBlob: genDEKResp.EncryptedDekBlob,
		Plaintext: istioIntermediateCaCSR,
		Aad: aadHashOfSelectedCsrTemplateFields,
	}); err != nil {
		logrus.Fatal(err)
		return err
	}


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
	logrus.Infof("Test 6 Returned AuthenticatedDecrypt (b64): %s", base64.URLEncoding.EncodeToString(adResp.Plaintext))


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
	   VerifyCertChain - take the CA-signed cert and hand over to verify the chain (chain not provided - currently assumes there's no intermediate and we only need the CA cert in the HSM to verify)
	*/
	logrus.Info("Test 7 VerifyCertChain")

    var signedCert []byte
	signedCert, err = dummyCaCertSigner(adResp.Plaintext)
	if nil != err {
		logrus.Fatalf("error signing cert by dummy CA")
		return err
	}

	chain := make([][]byte, 0)
	chain = append(chain, signedCert)

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



	return nil
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", ".sock"), "Unix Socket")
	testCmd.Flags().BoolVar(&loop, "loop", false, "Should we run the test in a loop?")
	testCmd.Flags().DurationVar(&loopTime, "loop-sleep", 10, "How many seconds to sleep between test runs ")
	testCmd.Flags().IntVar(&maxLoops, "max-loops", 100, "How many seconds to sleep between test runs ")

	testCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Timeout Duration")
	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// testCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// testCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}



func dummyCaCertSigner(p10Csr []byte) (signedCert []byte, err error) {

	var reloadedCsr *x509.CertificateRequest
	reloadedCsr, err = x509.ParseCertificateRequest(p10Csr)
	if nil != err {
		logrus.Fatal(err)
		return
	}

	var pemCaCertBlock *pem.Block
	pemCaCertBlock, _ = pem.Decode([]byte(dummyCaCert))
	var parsedRootCaCert *x509.Certificate
	parsedRootCaCert, err = x509.ParseCertificate(pemCaCertBlock.Bytes)
	if nil != err {
		logrus.Fatal(err)
		return
	}


	var pemKeyBlock *pem.Block
	pemKeyBlock, _ = pem.Decode([]byte(dummyCaPrivKey))
	var parsedCaPrivKey *rsa.PrivateKey
	parsedCaPrivKey, err = x509.ParsePKCS1PrivateKey(pemKeyBlock.Bytes)
	if nil != err {
		logrus.Fatal(err)
		return
	}

	// Sanity check
	if nil != reloadedCsr.CheckSignature() {
		logrus.Fatal(err)
		return
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

	signedCert, err = x509.CreateCertificate(rand.Reader, childTemplate, parsedRootCaCert, reloadedCsr.PublicKey, parsedCaPrivKey)
	if nil != err {
		logrus.Fatal(err)
		return
	}

	var loadedSignedCert = &x509.Certificate{}
	loadedSignedCert, err = x509.ParseCertificate(signedCert)
	if nil != err {
		logrus.Fatal(err)
		return
	}

	// Sanity check
	certPool := x509.NewCertPool()
	certPool.AddCert(parsedRootCaCert)
	_, err = loadedSignedCert.Verify(x509.VerifyOptions{Roots: certPool})
	if nil != err {
		logrus.Fatal(err)
		return
	}

    return
}