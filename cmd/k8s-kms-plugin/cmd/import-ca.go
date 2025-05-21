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
	"os"
	"path/filepath"
	"time"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// buffer to hold the CA certificate
var caCertPem []byte

// ViperFlagsImportCa defines a struct to hold the values of cobra CLI flags and use viper to populate them
type ViperFlagsImportCa struct {
	CaCertPath string `mapstructure:"cert-file"`
	CaID       string `mapstructure:"ca-id"`

	SocketPath string        `mapstructure:"socket"`
	Timeout    time.Duration `mapstructure:"timeout"`
}

// Declare the viper CLI flag values buffer
var vprFlgsImportCa ViperFlagsImportCa

// importCaCmd represents the import-ca command
var importCaCmd = &cobra.Command{
	Use:     "import-ca",
	Short:   "Import CA certificate",
	GroupID: "kmscmdsgrpsupporting",
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsImportCa); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Error("Error initializing Viper")
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var ictx context.Context
		var icancel context.CancelFunc
		var ic istio.KeyManagementServiceClient
		if ictx, icancel, ic, err = istio.GetClientSocket(vprFlgsImportCa.SocketPath, vprFlgsImportCa.Timeout); err != nil {
			return
		}
		defer icancel()

		if caCertPem, err = os.ReadFile(vprFlgsImportCa.CaCertPath); err != nil {
			return
		}
		req := &istio.ImportCACertRequest{
			CaId:       []byte(vprFlgsImportCa.CaID),
			CaCertBlob: caCertPem,
		}
		if _, err = ic.ImportCACert(ictx, req); err != nil {
			return
		}
		return
	},
}

func init() {
	rootCmd.AddCommand(importCaCmd)

	// Since this project uses Viper bind with Cobra flags, we generally do not need to use "Flags().*Var"
	// (like StringVar, BoolVar, Uint16Var, etc...) as we do not need to access the cobra flag values directly. This is
	// because we use Viper to retrieve the values of the flags.
	importCaCmd.Flags().StringP("cert-file", "f", "", "Certificate File. Env var: K8S_KMS_PLUGIN_IMPORT_CA_CERT_FILE")
	importCaCmd.MarkFlagRequired("cert-file")

	// Socket & Timeout
	importCaCmd.Flags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_IMPORT_CA_SOCKET")
	importCaCmd.Flags().Duration("timeout", 30*time.Second, "KMS timeout. Env var: K8S_KMS_PLUGIN_IMPORT_CA_TIMEOUT")
}
