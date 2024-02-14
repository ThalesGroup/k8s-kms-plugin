package cmd

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	"github.com/spf13/cobra"
)

var inName, outName string

type CSRSecret struct {
	KekID  string `json:"kek-id"`
	EncDEK string `json:"encrypted-dek"`
	CsrID  string `json:"csr-id"`
	EncCSR string `json:"encrypted-csr"`
}

var decryptCSRCmd = &cobra.Command{
	Use:   "decrypt-csr",
	Short: "Decrypt CSR",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := decryptCSR(); err != nil {
			return err
		}
		return nil
	},
}

func decryptCSR() error {
	csrJson, err := ioutil.ReadFile(inName)
	if err != nil {
		return fmt.Errorf("Couldn't open JSON CSR file: %v", err)
	}

	var csrSecret CSRSecret
	err = json.Unmarshal(csrJson, &csrSecret)
	if err != nil {
		return fmt.Errorf("Unmarshalling JSON failed: %v", err)
	}

	kekID, _ := b64.StdEncoding.DecodeString(csrSecret.KekID)
	encDEK, _ := b64.StdEncoding.DecodeString(csrSecret.EncDEK)
	csrID, _ := b64.StdEncoding.DecodeString(csrSecret.CsrID)
	encCSR, _ := b64.StdEncoding.DecodeString(csrSecret.EncCSR)

	if kekID == nil || encDEK == nil || csrID == nil || encCSR == nil {
		return fmt.Errorf("Base64 decoding secret failed")
	}

	ctx, cancel, c, err := istio.GetClientSocket(socketPath, timeout)
	defer cancel()
	if err != nil {
		return fmt.Errorf("Could not open socket: %v", err)
	}

	var adResp *istio.AuthenticatedDecryptResponse
	if adResp, err = c.AuthenticatedDecrypt(ctx, &istio.AuthenticatedDecryptRequest{
		KekKid:           kekID,
		EncryptedDekBlob: encDEK,
		Aad:              csrID,
		Ciphertext:       encCSR,
	}); err != nil {
		return fmt.Errorf("Failed to authenticate and decrypt CSR: %v", err)
	}

	fmt.Printf("KEK ID: %v\n", string(kekID))
	fmt.Printf("CSR ID: %v\n", string(csrID))

	if outName != "" {
		err = ioutil.WriteFile(outName, adResp.Plaintext, 0644)
		if err != nil {
			return fmt.Errorf("Couldn't write output file: %v", err)
		}
	} else {
		fmt.Printf("CSR:\n%v\n", string(adResp.Plaintext))
	}

	return nil
}

func init() {
	rootCmd.AddCommand(decryptCSRCmd)
	decryptCSRCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket")
	decryptCSRCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Timeout Duration")
	decryptCSRCmd.Flags().StringVarP(&inName, "inName", "f", "", "Input file")
	decryptCSRCmd.Flags().StringVarP(&outName, "outName", "o", "", "Output file")
}
