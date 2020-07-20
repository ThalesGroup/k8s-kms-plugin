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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/thales-e-security/estclient"
	"os"
)

var trustUnknownCA bool

// enrollCmd represents the init command
var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll to a k8s-kms-plugin endpoint",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		fmt.Println("enrolling")
		opts := estclient.ClientOptions{
			InsecureSkipVerify: trustUnknownCA,
			TLSTrustAnchor:     nil,
		}

		c := estclient.NewEstClientWithOptions(host, opts)

		ad := estclient.AuthData{

		}
		if clientID := os.Getenv("CLIENT_ID"); clientID != "" {
			ad.ID = &clientID
		}
		if clientSecret := os.Getenv("CLIENT_SECRET"); clientSecret != "" {
			ad.ID = &clientSecret
		}
		var fqdn string
		if fqdn, err = os.Hostname(); err != nil {
			return
		}
		req := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: fqdn,
			},
			Attributes:      nil,
			Extensions:      nil,
			ExtraExtensions: nil,
			DNSNames:        []string{fqdn, "localhost"},
			IPAddresses:     nil,
		}
		var clientCert *x509.Certificate
		if clientCert, err = c.SimpleEnroll(ad, req); err != nil {
			return
		}
		fmt.Printf("Issuer: %v\n", clientCert.Issuer)
		return
	},
}

func init() {
	rootCmd.AddCommand(enrollCmd)

	// Here you will define your flags and configuration settings.
	enrollCmd.Flags().BoolVarP(&trustUnknownCA, "trust-unknown-ca", "k", false, "Trust the EST CA's root CA... needed unless you have added this to your OS TrustStore")

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// enrollCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// enrollCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
