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
	importCaCmd.Flags().StringP("cert-file", "f", "", "Certificate File")
	importCaCmd.MarkFlagRequired("cert-file")

	// Socket & Timeout
	importCaCmd.Flags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_GENERATE_KEK_SOCKET")
	importCaCmd.Flags().Duration("timeout", 30*time.Second, "KMS timeout")
}
