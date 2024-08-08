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

	"github.com/ThalesGroup/k8s-kms-plugin/pkg/version"
	"github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

// CLI options pflags names
var outputFormat string // One of 'yaml' or 'json'.

// prettyPrintVersion defined by the user with flag --pretty
var prettyPrintVersion bool

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
		logrus.Debug("running command: k8s-kms-plugin version")

		// Add logic here to check if flag output is used with JSON or YAML.
		flagOutputUsed := cmd.Flags().Changed("output")
		flagPrettyUsed := cmd.Flags().Changed("pretty")

		if flagOutputUsed && !(outputFormat == "yaml" || outputFormat == "json") {
			logrus.Errorf("Invalid output format: %s. Must be json or yaml.", outputFormat)
		}

		if flagOutputUsed && flagPrettyUsed && outputFormat == "yaml" {
			logrus.Error("Flag --pretty must NOT be used when output format is yaml." +
				" --pretty is only used when output format is json")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), version.VersionOutputToString(outputFormat, prettyPrintVersion))
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	// Here you will define your flags and configuration settings.
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Format of the version output. One of 'yaml' or 'json'.")
	versionCmd.PersistentFlags().BoolVarP(&prettyPrintVersion, "pretty", "", true, "Activate pretty print output for JSON.")
}
