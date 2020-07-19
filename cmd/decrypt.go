/*
 * // Copyright 2020 Thales DIS CPL Inc
 * //
 * // Permission is hereby granted, free of charge, to any person obtaining
 * // a copy of this software and associated documentation files (the
 * // "Software"), to deal in the Software without restriction, including
 * // without limitation the rights to use, copy, modify, merge, publish,
 * // distribute, sublicense, and/or sell copies of the Software, and to
 * // permit persons to whom the Software is furnished to do so, subject to
 * // the following conditions:
 * //
 * // The above copyright notice and this permission notice shall be
 * // included in all copies or substantial portions of the Software.
 * //
 * // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * // EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * // NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * // LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * // OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * // WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package cmd

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1"
	"io/ioutil"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a Secret",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// determine the kind of data to send
		if inputFile != "" {
			if data, err = ioutil.ReadFile(inputFile); err != nil {
				return
			}
		} else if inputString != "" {
			data = []byte(inputString)
		}

		ctx, _, c, err := k8s.GetClient(host, port)
		var resp *k8s.DecryptResponse
		if resp, err = c.Decrypt(ctx, &k8s.DecryptRequest{
			Version: "version",
			Cipher:  data,
		}); err != nil {
			return
		}
		if outputFile != "" {
			if err = ioutil.WriteFile(outputFile, data, 0700); err != nil {
				logrus.Fatal(err)
			}
		} else {
			fmt.Println(string(resp.Plain))
		}
		return
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringVarP(&inputString, "string", "s", "", "String to decrypt")
	decryptCmd.Flags().StringVarP(&inputFile, "file", "f", "", "File to decrypt")
	decryptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for clear")

}
