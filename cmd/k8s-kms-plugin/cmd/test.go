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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"os"
	"path/filepath"
)

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test connectivety to the socket for some encrypt/decrypt",

	Run: func(cmd *cobra.Command, args []string) {
		// Istio Tests against the socket

		ctx, cancel, c, err := istio.GetClientSocket("test")
		defer cancel()
		if err != nil {
			logrus.Fatal(err)
		}
		var resp *istio.GenerateDEKResponse
		if resp, err = c.GenerateDEK(ctx, &istio.GenerateDEKRequest{
			Size: 32,
			Kind: istio.KeyKind_AES,
		}); err != nil {
			logrus.Fatal(err)
		}

		logrus.Infof("Returned WrappedDEK: %s", resp.EncryptedKeyBlob)

	},
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), ".sock"), "Unix Socket")

	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// testCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// testCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
