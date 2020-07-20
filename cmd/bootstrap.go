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
		if estca, err = ca.NewP11EST(caTLSCert, serverTLSKey, serverTLSCert, config); err != nil {
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
	bootstrapCmd.Flags().StringVar(&caTLSCert, "tls-ca", "certs/ca.crt", "EST TLS")
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
