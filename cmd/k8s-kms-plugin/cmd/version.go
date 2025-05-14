// MIT License
//
// Copyright (c) 2024 Thales. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"fmt"

	version "github.com/ThalesGroup/k8s-kms-plugin/pkg/version"
	"github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CLI options pflags names
var outputFormat string // One of 'yaml' or 'json'.

// prettyPrintVersion defined by the user with flag --pretty
var prettyPrintVersion bool

// ViperFlagsVersion defines a struct to hold the values of cobra CLI flags and use viper to populate them
type ViperFlagsVersion struct {
	OutputFormat       string `mapstructure:"output"`
	PrettyPrintVersion bool   `mapstructure:"pretty"`
}

// Declare the viper CLI flag values buffer
var vprFlgsVersion ViperFlagsVersion

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information.",
	Long: `Print the version information with various level of details
including information of the build and git repository metadata.

Examples:
  # print the version information with git repository details as a one liner
  # JSON string.
  k8s-kms-plugin version -o json --pretty=false`,
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsVersion); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Error("Error initializing Viper")
			return err
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Output version info
		fmt.Fprintln(cmd.OutOrStdout(), version.VersionOutputToString(vprFlgsVersion.OutputFormat, vprFlgsVersion.PrettyPrintVersion))
	},
}

func init() {
	// rootCmd is the parent command
	rootCmd.AddCommand(versionCmd)

	// Since this project uses Viper bind with Cobra flags, we generally do not need to use "Flags().*Var"
	// (like StringVar, BoolVar, Uint16Var, etc...) as we do not need to access the cobra flag values directly. This is
	// because we use Viper to retrieve the values of the flags.

	// Here you will define your flags and configuration settings.
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Format of the version output. One of 'yaml' or 'json'. Corresponding environment variable: K8S_KMS_PLUGIN_VERSION_OUTPUT")
	versionCmd.RegisterFlagCompletionFunc("output", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"yaml", "json"}, cobra.ShellCompDirectiveNoFileComp
	})
	versionCmd.Flags().BoolVarP(&prettyPrintVersion, "pretty", "P", true, "Activate pretty print output for JSON. Corresponding environment variable: K8S_KMS_PLUGIN_VERSION_PRETTY")
	versionCmd.RegisterFlagCompletionFunc("pretty", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"true", "false"}, cobra.ShellCompDirectiveNoFileComp
	})
}
