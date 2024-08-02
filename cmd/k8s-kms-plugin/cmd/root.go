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
	"github.com/keepeye/logrus-filename"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

var (
	socketPath string
	grpcPort   int64
	host       string
	cfgFile    string
	logOutput  string
	debug      bool
)

const (
	defaultKekId = "a37807cd-6d1a-4d75-813a-e120f30176f7"
	defaultCaId  = "1c3d30d5-dfa8-4167-a9f9-2c768464181b"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "",
	Short: "Thales KMS Server for K8S ",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		switch logOutput {
		case "json":
			logrus.SetFormatter(&logrus.JSONFormatter{})
		case "text":
			logrus.SetFormatter(&logrus.TextFormatter{
				ForceColors:      true,
				DisableTimestamp: true,
			})
		default:
			return errors.New("unknown format")
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	filenameHook := filename.NewHook()
	filenameHook.Field = "line"
	logrus.AddHook(filenameHook)
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
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

	rootCmd.Flags().BoolVar(&debug, "debug", false, "Debug")
	rootCmd.PersistentFlags().StringVar(&host, "host", "0.0.0.0", "TCP Host")
	rootCmd.PersistentFlags().Int64Var(&grpcPort, "port", 31400, "TCP Port for gRPC service")
	rootCmd.PersistentFlags().StringVar(&logOutput, "output", "text", "Log output format... text or json supported")
	// Provider
	rootCmd.PersistentFlags().StringVar(&provider, "provider", "p11", "Provider")
	rootCmd.PersistentFlags().StringVar(&kekKeyId, "kek-id", LookupEnvOrString("kek-id", defaultKekId), "Key ID for KMS KEK")
	rootCmd.PersistentFlags().StringVar(&caId, "ca-id", LookupEnvOrString("ca-id", defaultCaId), "Cert ID for CA Cert record")
	rootCmd.PersistentFlags().StringVar(&p11lib, "p11-lib", "", "Path to p11 library/client")
	rootCmd.PersistentFlags().StringVar(&p11label, "p11-label", "", "P11 token label")
	rootCmd.PersistentFlags().IntVar(&p11slot, "p11-slot", 0, "P11 token slot")
	rootCmd.PersistentFlags().StringVar(&p11pin, "p11-pin", "", "P11 Pin")
	rootCmd.PersistentFlags().StringVar(&defaultDekKeyName, "p11-key-label", "k8s-dek", "Key Label to use for encrypt/decrypt")
	rootCmd.PersistentFlags().StringVar(&hmacKeyName, "p11-hmac-label", "k8s-hmac", "Key Label to use for sha based verifications")
	rootCmd.PersistentFlags().StringVarP(&nativePath, "native-path", "p", ".keys", "Path to key store for native provider(Files only)")
	rootCmd.PersistentFlags().BoolVar(&createKey, "auto-create", false, "Auto create the keys if needed")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".k8ms" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName(".k8s-kms-plugin")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
func LookupEnvOrBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.ParseBool(val)
		if err != nil {
			return false
		}
		return v
	}
	return defaultVal
}
func LookupEnvOrInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			logrus.Info(err)
		}
		return v
	}
	return defaultVal
}
