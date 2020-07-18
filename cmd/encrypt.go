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
	"errors"
	"io/ioutil"
	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
	"os"

	"github.com/spf13/cobra"
)

var data []byte
var inputString string
var inputFile string
var outputFile string

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a secret",

	RunE: func(cmd *cobra.Command, args []string) (err error) {

		// determine the kind of data to send
		if inputFile != "" {
			if data, err = ioutil.ReadFile(inputFile); err != nil {
				return
			}
		} else if inputString != "" {
			data = []byte(inputString)
		} else {
			return errors.New("no file or string provided to encrypt")
		}

		ctx, _, c := getClient()

		var resp *v1beta1.EncryptResponse
		resp, err = c.Encrypt(ctx, &v1beta1.EncryptRequest{
			Version: "version",
			Plain:   data,
		})
		if err != nil {
			return
		}
		if outputFile != "" {
			if err = ioutil.WriteFile(outputFile, data, 0700); err != nil {
				return
			}
		} else {
			if _, err = os.Stdout.Write(resp.Cipher); err != nil {
				return
			}
		}
		return
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	// Here you will define your flags and configuration settings.
	encryptCmd.Flags().StringVarP(&inputString, "string", "s", "", "String to encrypt")
	encryptCmd.Flags().StringVarP(&inputFile, "file", "f", "", "File to encrypt")
	encryptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for payload")
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// encryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// encryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
