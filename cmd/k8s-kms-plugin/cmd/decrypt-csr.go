package cmd

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	"github.com/spf13/cobra"
)

// cobra decrypt-csr.go CLI Flags
var inName, outName string

// ViperFlagsDecryptCSR defines a struct to hold the configuration values and use viper.Unmarshal
// to populate it
type ViperFlagsDecryptCSR struct {
	Socket         string
	Timeout        time.Duration
	InputFilename  string `mapstructure:"input-filename"`
	OutputFilename string `mapstructure:"output-filename"`
}

// Declare the viper config struct with all the decrypt-csr CLI flags bound to viper env vars
var vprFlgsDecryptCSR ViperFlagsDecryptCSR

type CSRSecret struct {
	KekID  string `json:"kek-id"`
	EncDEK string `json:"encrypted-dek"`
	CsrID  string `json:"csr-id"`
	EncCSR string `json:"encrypted-csr"`
}

var decryptCSRCmd = &cobra.Command{
	Use:     "decrypt-csr",
	Short:   "Decrypt CSR",
	GroupID: "kmscmdsgrpsupporting",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := decryptCSR(); err != nil {
			return err
		}
		return nil
	},
}

func decryptCSR() error {
	csrJson, err := os.ReadFile(vprFlgsDecryptCSR.InputFilename)
	if err != nil {
		return fmt.Errorf("couldn't open JSON CSR file: %v", err)
	}

	var csrSecret CSRSecret
	err = json.Unmarshal(csrJson, &csrSecret)
	if err != nil {
		return fmt.Errorf("unmarshalling JSON failed: %v", err)
	}

	kekID, _ := b64.StdEncoding.DecodeString(csrSecret.KekID)
	encDEK, _ := b64.StdEncoding.DecodeString(csrSecret.EncDEK)
	csrID, _ := b64.StdEncoding.DecodeString(csrSecret.CsrID)
	encCSR, _ := b64.StdEncoding.DecodeString(csrSecret.EncCSR)

	if kekID == nil || encDEK == nil || csrID == nil || encCSR == nil {
		return fmt.Errorf("Base64 decoding secret failed")
	}

	ctx, cancel, c, err := istio.GetClientSocket(vprFlgsDecryptCSR.Socket, vprFlgsDecryptCSR.Timeout)
	defer cancel()
	if err != nil {
		return fmt.Errorf("could not open socket: %v", err)
	}

	var adResp *istio.AuthenticatedDecryptResponse
	if adResp, err = c.AuthenticatedDecrypt(ctx, &istio.AuthenticatedDecryptRequest{
		KekKid:           kekID,
		EncryptedDekBlob: encDEK,
		Aad:              csrID,
		Ciphertext:       encCSR,
	}); err != nil {
		return fmt.Errorf("failed to authenticate and decrypt CSR: %v", err)
	}

	fmt.Printf("KEK ID: %v\n", string(kekID))
	fmt.Printf("CSR ID: %v\n", string(csrID))

	if vprFlgsDecryptCSR.OutputFilename != "" {
		err = os.WriteFile(vprFlgsDecryptCSR.OutputFilename, adResp.Plaintext, 0644)
		if err != nil {
			return fmt.Errorf("couldn't write output file: %v", err)
		}
	} else {
		fmt.Printf("CSR:\n%v\n", string(adResp.Plaintext))
	}

	return nil
}

func init() {
	rootCmd.AddCommand(decryptCSRCmd)

	generateKEKCmd.Flags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_DECRYPT_CSR_SOCKET")
	generateKEKCmd.Flags().Duration("timeout", 5*time.Second, "KMS timeout")

	decryptCSRCmd.Flags().StringVarP(&inName, "input-filename", "f", "", "Input file")
	decryptCSRCmd.Flags().StringVarP(&outName, "output-filename", "o", "", "Output file")
}
