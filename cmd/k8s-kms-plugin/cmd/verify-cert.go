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
	"encoding/pem"
	"errors"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
)

var certChainPem []byte
var certChainPath string

// verifyCertCmd represents the verify-cert command
var verifyCertCmd = &cobra.Command{
	Use:   "verify-cert",
	Short: "Verify a cert chain in PEM format against a previously loaded CA",

	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var ictx context.Context
		var icancel context.CancelFunc
		var ic istio.KeyManagementServiceClient
		if ictx, icancel, ic, err = istio.GetClientSocket(socketPath, timeout); err != nil {
			return
		}
		defer icancel()

		if certChainPem, err = ioutil.ReadFile(certChainPath); err != nil {
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

	verifyCertCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket")
	verifyCertCmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "Timeout Duration")
	verifyCertCmd.Flags().StringVarP(&certChainPath, "cert-file", "f", "", "Cert Chain File ")
	verifyCertCmd.MarkFlagRequired("cert-file")
}
