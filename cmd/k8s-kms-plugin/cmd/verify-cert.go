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
	"context"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
)

// buffer to hold the cert chain
var certChainPem []byte

// ViperFlagsVerifyCert defines a struct to hold the values of cobra CLI flags and use viper to populate them
type ViperFlagsVerifyCert struct {
	CertChainPath string `mapstructure:"cert-file"`

	SocketPath string        `mapstructure:"socket"`
	Timeout    time.Duration `mapstructure:"timeout"`
}

// Declare the viper CLI flag values buffer
var vprFlgsVerifyCert ViperFlagsVerifyCert

// verifyCertCmd represents the verify-cert command
var verifyCertCmd = &cobra.Command{
	Use:     "verify-cert",
	Short:   "Verify a cert chain in PEM format against a previously loaded CA",
	GroupID: "kmscmdsgrpsupporting",
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsVerifyCert); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Error("Error initializing Viper")
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var ictx context.Context
		var icancel context.CancelFunc
		var ic istio.KeyManagementServiceClient
		if ictx, icancel, ic, err = istio.GetClientSocket(vprFlgsVerifyCert.SocketPath, vprFlgsVerifyCert.Timeout); err != nil {
			return
		}
		defer icancel()

		if certChainPem, err = os.ReadFile(vprFlgsVerifyCert.CertChainPath); err != nil {
			return
		}

		block, _ := pem.Decode(certChainPem)
		if block == nil || block.Type != "CERTIFICATE" {
			err = errors.New("failed to decode PEM block containing certificate")
			return
		}

		chain := make([][]byte, 0)
		chain = append(chain, block.Bytes)

		req := &istio.VerifyCertChainRequest{
			Certificates: chain,
		}
		if _, err = ic.VerifyCertChain(ictx, req); err != nil {
			return
		}
		return
	},
}

func init() {
	rootCmd.AddCommand(verifyCertCmd)

	// Since this project uses Viper bind with Cobra flags, we generally do not need to use "Flags().*Var"
	// (like StringVar, BoolVar, Uint16Var, etc...) as we do not need to access the cobra flag values directly. This is
	// because we use Viper to retrieve the values of the flags.

	verifyCertCmd.Flags().StringP("cert-file", "f", "", "Cert Chain File. Env var: K8S_KMS_PLUGIN_VERIFY_CERT_FILE")
	verifyCertCmd.MarkFlagRequired("cert-file")

	// Socket & Timeout
	verifyCertCmd.Flags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_VERIFY_CERT_SOCKET")
	verifyCertCmd.Flags().Duration("timeout", 10*time.Second, "KMS timeout. Env var: K8S_KMS_PLUGIN_VERIFY_CERT_TIMEOUT")
}
