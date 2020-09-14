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
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"io/ioutil"
)

var caCertPem []byte
var caCertPath string

// importCaCmd represents the importCa command
var importCaCmd = &cobra.Command{
	Use:   "import-ca",
	Short: "A brief description of your command",

	RunE: func(cmd *cobra.Command, args []string) (err error) {
		//
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
			KekKid:     nil,
			CaCertBlob: nil,
		}
		if _, err = ic.ImportCACert(ictx, req); err != nil {
			return
		}
		return

	},
}

func init() {
	rootCmd.AddCommand(importCaCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// importCaCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	importCaCmd.Flags().StringVar(&caCertPath, "cert-file", "", "Cert File ")
	importCaCmd.MarkFlagRequired("cert-file")
}
