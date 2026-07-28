// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"

	"log/slog"

	version "github.com/ThalesGroup/k8s-kms-plugin/pkg/version"

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
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsVersion); err != nil {
			slog.Error("Error initializing Viper", "cobra_cmd", cmd.Use, "error", err)
			return err
		}
		return nil
	},
	Run: func(cmd *cobra.Command, _ []string) {
		// Output version info
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), version.OutputToString(vprFlgsVersion.OutputFormat, vprFlgsVersion.PrettyPrintVersion)); err != nil {
			slog.Error("error writing version output", "error", err)
		}
	},
}

func init() {
	// rootCmd is the parent command
	rootCmd.AddCommand(versionCmd)

	// Since this project uses Viper bind with Cobra flags, we generally do not need to use "Flags().*Var"
	// (like StringVar, BoolVar, Uint16Var, etc...) as we do not need to access the cobra flag values directly. This is
	// because we use Viper to retrieve the values of the flags.

	// Here you will define your flags and configuration settings.
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Format of the version output. One of 'yaml' or 'json'. Env var: K8S_KMS_PLUGIN_VERSION_OUTPUT")
	if err := versionCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"yaml", "json"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		slog.Error("error registering flag completion function", "flag", "output", "error", err)
	}
	versionCmd.Flags().BoolVarP(&prettyPrintVersion, "pretty", "P", true, "Activate pretty print output for JSON. Env var: K8S_KMS_PLUGIN_VERSION_PRETTY")
	if err := versionCmd.RegisterFlagCompletionFunc("pretty", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"true", "false"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		slog.Error("error registering flag completion function", "flag", "pretty", "error", err)
	}
}
