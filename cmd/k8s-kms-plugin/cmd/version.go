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
	"strings"

	"github.com/ThalesGroup/k8s-kms-plugin/pkg/version"
	"github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"os"
)

// CLI options pflags names
var outputFormat string // One of 'yaml' or 'json'.

// prettyPrintVersion defined by the user with flag --pretty
var prettyPrintVersion bool

// ViperFlagsVersion defines a struct to hold all the configuration values and use viper.Unmarshal
// to populate it:
type ViperFlagsVersion struct {
	OutputFormat       string `mapstructure:"output"`
	PrettyPrintVersion bool   `mapstructure:"pretty"`
}

// Initialize the ViperConfig struct with all the version CLI flags bound to Viper env vars
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
	Run: func(cmd *cobra.Command, args []string) {
		// Ensure all Cobra flags are bound to Viper
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			logrus.Errorf("Error binding flags: %v", err)
			os.Exit(1)
		}

		// Always set env var prefix for consistency
		viper.SetEnvPrefix("K8S_KMS_PLUGIN")
		viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
		viper.AutomaticEnv()

		// Extract "version" config if present
		vprSubBuf := viper.Sub("version")

		// If config exists, bind its values
		if vprSubBuf != nil {
			logrus.Tracef("A 'version' section found in %s", viper.ConfigFileUsed())

			// Apply env vars to sub-Viper instance

			vprSubBuf.SetEnvPrefix("K8S_KMS_PLUGIN")
			vprSubBuf.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
			vprSubBuf.AutomaticEnv()

			// Re-bind flags at the sub-Viper level
			if err := vprSubBuf.BindPFlags(cmd.Flags()); err != nil {
				logrus.Errorf("Error binding flags: %v", err)
				os.Exit(1)
			}

			// Merge config from file + env vars + flags
			if err := vprSubBuf.Unmarshal(&vprFlgsVersion); err != nil {
				logrus.WithError(err).Fatal("versionCmd: failed to unmarshal viper config")
			}

			// Override with environment variables manually
			if envVal := viper.GetString("output"); envVal != "" {
				vprFlgsVersion.OutputFormat = envVal
			}
			if envVal := viper.GetBool("PRETTY"); envVal {
				vprFlgsVersion.PrettyPrintVersion = envVal
			}

		} else {
			logrus.Tracef("No 'version' section found, using root-level Viper settings.")

			// Use root-level Viper config if no sub-config exists
			if err := viper.Unmarshal(&vprFlgsVersion); err != nil {
				logrus.WithError(err).Fatal("versionCmd: failed to unmarshal viper config")
			}
		}

		// Debug: print the final configuration
		logrus.Infof("Final Config: %+v", vprFlgsVersion)

		// Output version info
		fmt.Fprintln(cmd.OutOrStdout(), version.VersionOutputToString(vprFlgsVersion.OutputFormat, vprFlgsVersion.PrettyPrintVersion))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	// Here you will define your flags and configuration settings.
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Format of the version output. One of 'yaml' or 'json'.")
	versionCmd.RegisterFlagCompletionFunc("output", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"yaml", "json"}, cobra.ShellCompDirectiveNoFileComp
	})
	versionCmd.Flags().BoolVar(&prettyPrintVersion, "pretty", true, "Activate pretty print output for JSON.")
	versionCmd.RegisterFlagCompletionFunc("pretty", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"true", "false"}, cobra.ShellCompDirectiveNoFileComp
	})
}
