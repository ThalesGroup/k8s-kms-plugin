/*
 * // Copyright 2024 Thales Group 2020 Thales DIS CPL Inc
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
	"fmt"
	"path/filepath"
	"strconv"

	filename "github.com/keepeye/logrus-filename"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"

	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// cobra root CLI flags
var (
	socketPath      string
	grpcPort        int64
	host            string
	cfgFile         string
	debug           bool
	logLevel        string
	logFormat       string
	caId            string
	createKey       bool
	dekKeyLabelName string
	hmacKeyName     string
	kekKeyId        string
	nativePath      string
	p11label        string
	p11lib          string
	p11pin          string
	p11slot         int
	provider        string
)

// cobra root CLI flags default value
const (
	defaultKekId = "a37807cd-6d1a-4d75-813a-e120f30176f7"
	defaultCaId  = "1c3d30d5-dfa8-4167-a9f9-2c768464181b"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "k8s-kms-plugin",
	Short: "Thales KMS Server for K8S",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize logrus log level and log format for all cobra commands and subcommands.
		// TODO: debug flag should be replaced a log-level flag, or a log-level should be added in addition to the debug flag
		// https://github.com/ThalesGroup/k8s-kms-plugin/issues/46
		// https://github.com/ThalesGroup/k8s-kms-plugin/issues/47
		debugFlagIsUsed := cmd.Flags().Lookup("debug").Changed

		switch {
		case debugFlagIsUsed:
			// harcode that the --debug flags set logrus to debug
			logrus.SetLevel(logrus.DebugLevel)
		default:
			level, err := logrus.ParseLevel(logLevel)
			if err != nil {
				return err
			}
			logrus.SetLevel(level)
		}
		logrus.Debugf("logrus log-level is set to: %s", logrus.GetLevel())

		switch logFormat {
		case "json":
			logrus.SetFormatter(&logrus.JSONFormatter{})
		case "text":
			logrus.SetFormatter(&logrus.TextFormatter{
				ForceColors:      true,
				DisableTimestamp: true,
			})
		default:
			return errors.New("logrus unknown output format")
		}
		logrus.Debugf("logrus output format is set to: %s", logFormat)

		// Initialize the value of socketPath
		// TODO: should SOCKET be called P11_SOCKET to be more consistent with other numbering?
		getValueFromCliFlagOrEnv(cmd, "socket", "SOCKET", &socketPath)

		// Initialize the value of p11lib
		getValueFromCliFlagOrEnv(cmd, "p11-lib", "P11_LIBRARY", &p11lib)

		// Initialize the value of p11label
		getValueFromCliFlagOrEnv(cmd, "p11-label", "P11_TOKEN", &p11label)

		// Initialize the value of p11slot
		getValueFromCliFlagOrEnv(cmd, "p11-slot", "P11_SLOT", &p11slot)

		// Initialize the value of p11pin
		getValueFromCliFlagOrEnv(cmd, "p11-pin", "P11_PIN", &p11pin)

		// TODO Choose wether each CLI flag should have a corresponding environment variable or not.
		// TODO Choose wether the initialization (cli, env var or default value) should be done in the PersistentPreRunE
		// or if it should be done in a separate function that could be called in the PersistentPreRunE.

		// PersistentPreRunE returns an error or nil
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	filenameHook := filename.NewHook()
	filenameHook.Field = "line"
	logrus.AddHook(filenameHook)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "ConfigFile)")

	// logging level
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Set logrus.SetLevel to \"debug\". This is equivalent to using --log-level=debug. Do not use this flag at the same time as --log-level. The flag --log-level takes precedence over --debug flag.")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Set logrus.SetLevel. Logrus has seven logging levels: trace, debug, info, warning, error, fatal and panic. The flag --log-level takes precedence over --debug flag.")
	rootCmd.RegisterFlagCompletionFunc("log-level", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"trace", "debug", "info", "warning", "error", "fatal", "panic"}, cobra.ShellCompDirectiveNoFileComp
	})
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "text", "Logrus log output format... text or json supported")
	rootCmd.RegisterFlagCompletionFunc("log-format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"text", "json"}, cobra.ShellCompDirectiveNoFileComp
	})
	rootCmd.MarkFlagsMutuallyExclusive("log-level", "debug")

	rootCmd.PersistentFlags().StringVar(&host, "host", "0.0.0.0", "Hostname without port")
	rootCmd.PersistentFlags().Int64Var(&grpcPort, "port", 31400, "TCP Port for gRPC service")
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Corresponding environment variable: SOCKET")
	// Provider
	rootCmd.PersistentFlags().StringVar(&provider, "provider", "p11", "Provider (accepts: p11, softhsm, luna, dpod)")
	rootCmd.RegisterFlagCompletionFunc("provider", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"p11", "softhsm", "luna", "dpod"}, cobra.ShellCompDirectiveNoFileComp
	})
	rootCmd.PersistentFlags().StringVar(&kekKeyId, "kek-id", defaultKekId, "Key ID for KMS KEK")
	rootCmd.PersistentFlags().StringVar(&caId, "ca-id", defaultCaId, "Cert ID for CA Cert record")
	rootCmd.PersistentFlags().StringVar(&p11lib, "p11-lib", "", "Path to p11 library/client. Corresponding environment variable: P11_LIBRARY")
	rootCmd.PersistentFlags().StringVar(&p11label, "p11-label", "", "P11 token label. Corresponding environment variable: P11_TOKEN")
	rootCmd.PersistentFlags().IntVar(&p11slot, "p11-slot", 0, "P11 token slot. Corresponding environment variable: P11_SLOT")
	rootCmd.PersistentFlags().StringVar(&p11pin, "p11-pin", "", "P11 Pin. Corresponding environment variable: P11_PIN")
	rootCmd.PersistentFlags().StringVar(&dekKeyLabelName, "p11-key-label", "k8s-dek", "Key Label to use for encrypt/decrypt")
	rootCmd.PersistentFlags().StringVar(&hmacKeyName, "p11-hmac-label", "k8s-hmac", "Key Label to use for sha based verifications")
	rootCmd.PersistentFlags().StringVarP(&nativePath, "native-path", "p", ".keys", "Path to key store for native provider(Files only)")
	rootCmd.PersistentFlags().BoolVar(&createKey, "auto-create", false, "Auto create the keys if needed")

	// validates all the mutuallyExclusive/oneRequired/requiredAsGroup
	rootCmd.ValidateFlagGroups()
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		logrus.Debugf("Using config file from the flag: %s", cfgFile)
		viper.SetConfigFile(cfgFile)
	} else {
		// TODO: check if this is still relevant to auto search a config file, and check config file default names
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		logrus.Debugf("Search config in home directory %s with name \".k8ms\" (without extension).", home)
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName(".k8s-kms-plugin")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logrus.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
}

// getValueFromCliFlagOrEnv retrieves the value of a user configuration setting based on the
// priority of sources. It first checks if the cobra CLI flag specified by 'flagName' has been set
// and used by user. If the CLI flag is set, its value is used by cobra. If the flag is not set, it
// checks if the environment variable 'envName' is set, using its value if available. If
// neither the flag nor the environment variable is set, the function exit and do nothing, which
// means the default cobra flags value is used.
// cliFlagValueStoreVar is the variable that holds the value of a given cobra flag.
//
// getValueFromCliFlagOrEnv supports the following types for cliFlagValueStoreVar: *int and *string
//
// example
// Initialize the value of socketPath. The value from the cobra CLI flag --socket has the
// priority over the value from the environment variable SOCKET. If the CLI flag is set, the
// value from the CLI flag is used and the environment variable is ignored. If the CLI flag
// is not set and if the environment variable is used, the value from the environment
// variable is used. If neither the CLI flag nor the environment variable is set, the
// default value is used.
func getValueFromCliFlagOrEnv(cmd *cobra.Command, cliFlagName string, envVarName string, cliFlagValueStoreVar interface{}) {
	switch v := cliFlagValueStoreVar.(type) {
	case *string:
		if !cmd.Flags().Lookup(cliFlagName).Changed {
			if a, ok := os.LookupEnv(envVarName); ok {
				logrus.Debugf("--%s flag is not used. Environment variable %s is set to: %s", cliFlagName, envVarName, a)
				*v = a
				return
			}
			logrus.Debugf("--%s flag is not used. Environment variable %s is not set. Using default value: %s", cliFlagName, envVarName, *v)
			return
		}
		logrus.Debugf("--%s flag is used. Using value from --%s flag: %s", cliFlagName, cliFlagName, *v)
	case *int:
		if !cmd.Flags().Lookup(cliFlagName).Changed {
			if a, ok := os.LookupEnv(envVarName); ok {
				if val, err := strconv.Atoi(a); err == nil {
					logrus.Debugf("--%s flag is not used. Environment variable %s is set to: %d", cliFlagName, envVarName, val)
					*v = val
					return
				}
			}
			logrus.Debugf("--%s flag is not used. Environment variable %s is not set. Using default value: %d", cliFlagName, envVarName, *v)
			return
		}
		logrus.Debugf("--%s flag is used. Using value from --%s flag: %d", cliFlagName, cliFlagName, *v)
	default:
		logrus.Errorf("Unsupported type for flags %s and environment variable %s", cliFlagName, envVarName)
	}
}
