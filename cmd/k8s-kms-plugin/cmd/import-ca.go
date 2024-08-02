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
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	"github.com/spf13/cobra"
)

var caCertPem []byte
var caCertPath string

// importCaCmd represents the import-ca command
var importCaCmd = &cobra.Command{
	Use:   "import-ca",
	Short: "Import CA certificate",

	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var ictx context.Context
		var icancel context.CancelFunc
		var ic istio.KeyManagementServiceClient
		if ictx, icancel, ic, err = istio.GetClientSocket(socketPath, timeout); err != nil {
			return
		}
		defer icancel()

		if caCertPem, err = ioutil.ReadFile(caCertPath); err != nil {
			return
		}
		req := &istio.ImportCACertRequest{
			CaId:       []byte(caId),
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

	importCaCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket")
	importCaCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Timeout Duration")
	importCaCmd.Flags().StringVarP(&caCertPath, "cert-file", "f", "", "Certificate File")
	importCaCmd.MarkFlagRequired("cert-file")
}
