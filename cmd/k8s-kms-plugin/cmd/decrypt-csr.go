/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package cmd

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ViperFlagsDecryptCSR defines a struct to hold the values of cobra CLI flags and use viper to populate them
type ViperFlagsDecryptCSR struct {
	InputFilename  string `mapstructure:"input-filename"`
	OutputFilename string `mapstructure:"output-filename"`

	Socket  string        `mapstructure:"socket"`
	Timeout time.Duration `mapstructure:"timeout"`
}

// Declare the viper CLI flag values buffer
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
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsDecryptCSR); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Error("Error initializing Viper")
			return err
		}
		return nil
	},
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

	// Since this project uses Viper bind with Cobra flags, we generally do not need to use "Flags().*Var"
	// (like StringVar, BoolVar, Uint16Var, etc...) as we do not need to access the cobra flag values directly. This is
	// because we use Viper to retrieve the values of the flags.
	decryptCSRCmd.Flags().StringP("input-filename", "f", "", "Input file. Env var: K8S_KMS_PLUGIN_DECRYPT_CSR_INPUT_FILE")
	decryptCSRCmd.Flags().StringP("output-filename", "o", "", "Output file. Env var: K8S_KMS_PLUGIN_DECRYPT_CSR_OUTPUT_FILE")

	// Socket & Timeout
	decryptCSRCmd.Flags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_DECRYPT_CSR_SOCKET")
	decryptCSRCmd.Flags().Duration("timeout", 30*time.Second, "KMS timeout. Env var: K8S_KMS_PLUGIN_DECRYPT_CSR_TIMEOUT")
}
