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
	"flag"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/ca"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var estca *ca.P11

// bootstrapCmd represents the bootstrap command
var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Bootstrap/regenerate EST PKI",

	RunE: func(cmd *cobra.Command, args []string) (err error) {
		flag.Parse()
		fmt.Println("bootstrap called")
		if a := os.Getenv("P11_LIB"); a != "" {
			p11lib = a
		}
		if a := os.Getenv("P11_LABEL"); a != "" {
			p11label = a
		}
		if a := os.Getenv("P11_SLOT"); a != "" {
			if p11slot, err = strconv.Atoi(a); err != nil {
				return
			}
		}
		if a := os.Getenv("P11_PIN"); a != "" {
			p11pin = a
		}
		config := &crypto11.Config{
			Path:            p11lib,
			TokenLabel:      p11label,
			Pin:             p11pin,
			UseGCMIVFromHSM: true,
		}
		if estca, err = ca.NewP11EST(caTLSCert, serverTLSKey, serverTLSCert, estKeyId, config); err != nil {
			return
		}
		if err = estca.BootstrapCA(); err != nil {
			return
		}

		return
	},
}

func init() {
	rootCmd.AddCommand(bootstrapCmd)

	// Here you will define your flags and configuration settings.
	bootstrapCmd.Flags().StringVar(&caTLSCert, "tls-ca.go", "certs/ca.go.crt", "EST TLS")
	bootstrapCmd.Flags().StringVar(&serverTLSKey, "tls-key", "certs/tls.key", "Key for Server TLS")
	bootstrapCmd.Flags().StringVar(&serverTLSCert, "tls-certificate", "certs/tls.crt", "Cert for Server TLS")
	bootstrapCmd.Flags().StringVar(&p11lib, "p11-lib", "", "Path to p11 library/client")
	bootstrapCmd.Flags().StringVar(&p11label, "p11-label", "", "P11 token label")
	bootstrapCmd.Flags().IntVar(&p11slot, "p11-slot", 0, "P11 token slot")
	bootstrapCmd.Flags().StringVar(&p11pin, "p11-pin", "", "P11 Pin")
	bootstrapCmd.Flags().StringVar(&keyName, "p11-key-label", "k8s-kek", "Key Label to use for encrypt/decrypt")
	bootstrapCmd.Flags().BoolVar(&createKey, "auto-create", false, "Auto create the key")
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// bootstrapCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// bootstrapCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
