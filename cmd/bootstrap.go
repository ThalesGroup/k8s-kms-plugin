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
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/ca"

	"github.com/spf13/cobra"
)

type bootstrapConfig struct {
	Ca   string
	Key  string
	Cert string
}

var bsConfig = &bootstrapConfig{

}
var estca *ca.P11

// bootstrapCmd represents the bootstrap command
var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Bootstrap/regenerate EST PKI",

	RunE: func(cmd *cobra.Command, args []string) (err error) {
		fmt.Println("bootstrap called")
		config := &crypto11.Config{
			Path:            p11lib,
			TokenLabel:      p11label,
			Pin:             p11pin,
			UseGCMIVFromHSM: true,
		}
		if estca, err = ca.NewP11EST(bsConfig.Ca, bsConfig.Key, bsConfig.Cert, config); err != nil {
			return
		}

		return
	},
}

func init() {
	rootCmd.AddCommand(bootstrapCmd)

	// Here you will define your flags and configuration settings.
	bootstrapCmd.Flags().StringVar(&bsConfig.Ca, "est-ca", "/certs/ca.crt", "CA Cert in PEM format")
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// bootstrapCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// bootstrapCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
