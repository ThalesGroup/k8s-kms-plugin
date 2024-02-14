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
	"golang.org/x/sync/errgroup"
	"hash"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
)

var loop bool
var maxLoops int
var loopTime, timeout time.Duration

const dummyCaCert = "-----BEGIN CERTIFICATE-----\nMIIGADCCA7SgAwIBAgIQAzUe9pVQo20RU9LSiRiDkDBBBgkqhkiG9w0BAQowNKAP\nMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMC\nASAwLTEQMA4GA1UEChMHQWNtZSBDbzEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNv\nbTAeFw0yMDA5MTUxMDEwNTlaFw0zMDA5MTMxMDEwNTlaMC0xEDAOBgNVBAoTB0Fj\nbWUgQ28xGTAXBgNVBAMTEHRlc3QuZXhhbXBsZS5jb20wggIiMA0GCSqGSIb3DQEB\nAQUAA4ICDwAwggIKAoICAQCuaGKyDvJ0ebW/9Kq7fltuLZhWQJb613EcHc2eV7ht\nejffCYklRJeKONhkozroxsb5y0ETvlWRiBDVBj0Zq0dyHY781N/QJZcBons0cRXV\nYNBd4nUaJ//FufzI1mbSXohpSaV1hkoQ2uTqB4B7yUWaiM1nIx1snzdXJSGhVYxy\nRhdTHMNd/z8ut+dwRojFIiU7S5NXaCc9LL9LryXy1N+VZo6sHK6NZQu27ryE7wv1\nh+bvG6TsfIsmfcv94ghX94olxY/+h38sDrX3LboKt3j8Tktg3amnwuKENYnvTOMZ\nkHkofj6k8kx+lCzJLDi2hCcq3r3ZPoT146mU5v3nwGF0zPSN3+GertuI9rmSvUy+\ngeD5QeWczUgADaALMVBTQY+wEBNhzyWa6O/l/yPErW2epFSibHIyz+97Nlen9CaF\nKBAUhRYVJIaUOCPmCK5VW4ghadF8zflUsgo5s/himfs9CWF12yAEYS1MjhyTTmAa\n0/DymJ0M8kaTuVUoQW6rrPGAzVRQEBeeVa3OJY6mPvOq0XosYGXtROSq9DMPGwcy\no9OlXhw6uD/rBPxNC8cqDZviM3QHKoN4lGatgfuSrowIU5Bi1yzgMxKdouY78OEI\nThtQTw2XxdoUy+Vr0XlQg9gAJqP0mq1O8fu7zjhua9k8Pdm6B0fxGsBa0Yz4MMQn\nIwIDAQABo4GzMIGwMA4GA1UdDwEB/wQEAwICBDAdBgNVHSUEFjAUBggrBgEFBQcD\nAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zANBgNVHQ4EBgQEAQIDBDBfBggr\nBgEFBQcBAQRTMFEwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmV4YW1wbGUuY29t\nMCoGCCsGAQUFBzAChh5odHRwOi8vY3J0LmV4YW1wbGUuY29tL2NhMS5jcnQwQQYJ\nKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglg\nhkgBZQMEAgEFAKIDAgEgA4ICAQCfFnc0Cajm48LiDw2NxSsNMCGCT/uju6KJG3O8\naXG6rEorDJs3uWCdyn6PhzyhqEdPGiBfJVJnmY9OfF8wWx3zXVAxstOp1RIrA3yI\nfIZAMoTsAYYKXH9gMda9wcPMFOFKrjbmDJKk8c3WwXth5NIeqqQPGTTh0ovHVc8Q\nHDSZo3lyBEmUDjrF2qu0VGn4m2kuxFl8lPUAu8lUR2+KLj6XStqhDd6gXCa2/quZ\nSROFRccS5bPEwJh7l1QSqhwHjS0oKU0sIGq6+VPq2TKUcf4F1zaw4dOKqhBbm+o1\nN7K49deaQH3Zb40jR7f2Rw+s86MM1ujS8tu98yRcu8+KPq1vb1fOQlG/UnOAtYd7\n8kej0ot/QYb7NxDqxNqW2vePbkUoOHV9TtRNQDV0hQooWB/GzZGWUrILDRugDwH+\nX7XNzC5ov1TbRpXkvmpBkY80oBFb9P4bCtUb2dmcdxM7KM5dnoHOQ8Fb7aSWcstE\nSOI2qbSnl2/uigjWLayWpn6k1OTszsLQTxAcezNLL6cTI+eWb3oC0KoAP458FtNH\nb/W8F2WNIxCjD9ydVU2JFPRSy1FfAQFhNMPwyIoT4AZ46G/u4gNu/AIPERfCUqdG\nQWUMsGgTs6NVDmo5YeasplU5uYyEvqPnUhZFsxNSPu/wmDiIcjrtIeEym7Dq4MiG\neOMvxQ==\n-----END CERTIFICATE-----"
const dummyIntermediateCaCert = "-----BEGIN CERTIFICATE-----\n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\nijrJCBNELSQ8gsZSfXBJ/MEkXA==\n-----END CERTIFICATE-----"
const dummyBadCaCert = "-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----"
const dummyBadCaPrivKey = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----"
const dummyCaPrivKey = "-----BEGIN PRIVATE KEY-----\n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\n-----END PRIVATE KEY-----\n"
const dummyIntermediateCaPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----"

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
	Short: "Test connectivity to the socket for some encrypt/decrypt",

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
	var kekUuid, caUuid uuid.UUID
	var kekKid, caKid []byte
	kekUuid, err = uuid.NewRandom()
	if err != nil {
		return err
	}
	caUuid, err = uuid.NewRandom()
	if err != nil {
		return err
	}
	kekKid, err = kekUuid.MarshalText()
	if err != nil {
		return err
	}
	caKid, err = caUuid.MarshalText()
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

	/*
		AuthenticatedDecrypt
	*/
	logrus.Info("Test 6 AuthenticatedDecrypt ")
	var adResp *istio.AuthenticatedDecryptResponse
	if adResp, err = ic.AuthenticatedDecrypt(ictx, &istio.AuthenticatedDecryptRequest{
		KekKid:           genKEKResp.KekKid,
		EncryptedDekBlob: genDEKResp.EncryptedDekBlob,
		Ciphertext:       aeResp.Ciphertext,
		Aad:              aadHashOfSelectedCsrTemplateFields,
	}); err != nil {
		logrus.Fatal(err)
		return err
	}
	logrus.Infof("Test 6 Returned AuthenticatedDecrypt (b64): %s", base64.URLEncoding.EncodeToString(adResp.Plaintext))

	logrus.Info("Test 7 ImportCACert ")

	var icResp *istio.ImportCACertResponse
	if icResp, err = ic.ImportCACert(ictx, &istio.ImportCACertRequest{
		CaId:       caKid,
		CaCertBlob: []byte(dummyCaCert),
	}); err != nil {
		logrus.Fatal(err)
		return err
	}

	logrus.Infof("Test 7 Returned ImportCACert: %v", icResp.Success)

	/*
	   VerifyCertChain - take the CA-signed cert and hand over to verify the chain (chain not provided - currently assumes there's no intermediate and we only need the CA cert in the HSM to verify)
	*/
	logrus.Info("Test 8 VerifyCertChain (only target cert)")

	var signedCert []byte
	signedCert, err = dummyCaCertSigner(adResp.Plaintext, dummyCaCert, dummyCaPrivKey)
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

	/*
	   VerifyCertChain - provides the target cert and the root cert (which matches one already in the HSM)
	*/

	logrus.Info("Test 9 VerifyCertChain (target cert and root cert - check that root cert matches one in the HSM)")
	chain = nil
	chain = make([][]byte, 0)
	// Append the root cert first
	// TODO - Need to change this so it's PEM throughout
	chain = append(chain, []byte(dummyCaCert))
	chain = append(chain, signedCert)

	verifyCertChainReq.Certificates = chain

	if verifyCertChainResp, err = ic.VerifyCertChain(ictx, verifyCertChainReq); nil != err {
		logrus.Fatal(err)
		return err
	}

	if !verifyCertChainResp.SuccessfulVerification {
		logrus.Fatal("VerifyCertChain returned false")
		return fmt.Errorf("VerifyCertChain returned false")
	}

	/*
	   VerifyCertChain - provides the target cert and an intermediate cert (which verifies against one already in the HSM)
	*/

	logrus.Info("Test 10 VerifyCertChain (target cert and intermediate cert)")

	var intermediateForSigningPrivKey *rsa.PrivateKey
	intermediateForSigningPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)

	var csrIntermediateTemplateForSigning = &x509.CertificateRequest{
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

	var istioIntermediateCaCSRForEnd []byte
	if istioIntermediateCaCSRForEnd, err = x509.CreateCertificateRequest(rand.Reader, csrIntermediateTemplateForSigning, intermediateForSigningPrivKey); nil != err {
		logrus.Fatal(err)
		return err
	}

	var signedCertByIntermediate []byte
	signedCertByIntermediate, err = dummyCaCertSigner(istioIntermediateCaCSRForEnd, dummyIntermediateCaCert, dummyIntermediateCaPrivateKey)

	chain = nil
	chain = make([][]byte, 0)
	// Append the intermediate cert first
	// TODO - Need to change this so it's PEM throughout

	chain = append(chain, []byte(dummyIntermediateCaCert))
	chain = append(chain, signedCertByIntermediate)

	verifyCertChainReq.Certificates = chain

	if verifyCertChainResp, err = ic.VerifyCertChain(ictx, verifyCertChainReq); nil != err {
		logrus.Fatal(err)
		return err
	}

	if !verifyCertChainResp.SuccessfulVerification {
		logrus.Fatal("VerifyCertChain returned false")
		return fmt.Errorf("VerifyCertChain returned false")
	}

	/*
	   VerifyCertChain - provides the target cert which fails to verify against any cert in the HSM
	   We corrupt the signature
	*/

	logrus.Info("Test 11 VerifyCertChain (only target cert - negative)")

	badCert, _ := x509.ParseCertificate(signedCert)
	badCert.Signature[42] ^= badCert.Signature[42]

	chain = nil
	chain = append(chain, badCert.Raw)

	verifyCertChainReq = &istio.VerifyCertChainRequest{
		Certificates: chain,
	}
	verifyCertChainResp = &istio.VerifyCertChainResponse{}
	if verifyCertChainResp, err = ic.VerifyCertChain(ictx, verifyCertChainReq); nil == err {
		err = fmt.Errorf("expected error but received none")
		return err
	}

	/*
	   VerifyCertChain - provides the target cert and the root cert (which fails to match the one already in the HSM,
	   but the provided chain verifies)
	*/

	logrus.Info("Test 12 VerifyCertChain (target cert and root cert - negative - root cert does not match loaded)")

	chain = nil
	chain = make([][]byte, 0)
	// Append the root cert first
	// TODO - Need to change this so it's PEM throughout
	chain = append(chain, []byte(dummyBadCaCert))

	var signedCertByBadCa []byte
	signedCertByBadCa, err = dummyCaCertSigner(adResp.Plaintext, dummyBadCaCert, dummyBadCaPrivKey)
	if nil != err {
		logrus.Fatalf("%v", err.Error())
		return err
	}

	chain = append(chain, signedCertByBadCa)
	verifyCertChainReq.Certificates = chain

	if verifyCertChainResp, err = ic.VerifyCertChain(ictx, verifyCertChainReq); nil == err {
		err = fmt.Errorf("expected error but received none")
		return err
	}

	return nil
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket")
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

func dummyCaCertSigner(p10Csr []byte, pemCaCert, pemCaPrivKey string) (signedCert []byte, err error) {

	var reloadedCsr *x509.CertificateRequest
	reloadedCsr, err = x509.ParseCertificateRequest(p10Csr)
	if nil != err {
		logrus.Fatal(err)
		return
	}

	var pemCaCertBlock *pem.Block
	pemCaCertBlock, _ = pem.Decode([]byte(pemCaCert))
	var parsedRootCaCert *x509.Certificate
	parsedRootCaCert, err = x509.ParseCertificate(pemCaCertBlock.Bytes)
	if nil != err {
		logrus.Fatal(err)
		return
	}

	var pemKeyBlock *pem.Block
	pemKeyBlock, _ = pem.Decode([]byte(pemCaPrivKey))
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
			CommonName:   reloadedCsr.Subject.CommonName,
		},

		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		PublicKeyAlgorithm: x509.RSA,

		SubjectKeyId: []byte{1, 2, 3, 4},

		IsCA: true,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 10),

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
