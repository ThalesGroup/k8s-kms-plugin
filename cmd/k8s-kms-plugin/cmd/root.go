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
	"strings"

	filename "github.com/keepeye/logrus-filename"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"

	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// cobra root CLI flags. They are mostly not used because we use viper that binds the cobra flags
// to the corresponding environment variables that viper reads.
var (
	caId            string
	cfgFile         string
	createKey       bool
	debug           bool
	dekKeyLabelName string
	grpcPort        int64
	hmacKeyName     string
	host            string
	kekKeyId        string
	logFormat       string
	logLevel        string
	nativePath      string
	p11label        string
	p11lib          string
	p11pin          string
	p11slot         int
	provider        string
	socketPath      string
)

// ViperConfig defines a struct to hold all the configuration values and use viper.Unmarshal
// to populate it:
type ViperConfig struct {
	CaID         string `mapstructure:"ca-id"`
	ConfigFile   string `mapstructure:"config"`
	CreateKey    bool   `mapstructure:"auto-create"`
	Debug        bool   `mapstructure:"debug"`
	DekKeyLabel  string `mapstructure:"p11-key-label"`
	HmacKeyLabel string `mapstructure:"p11-hmac-label"`
	Host         string `mapstructure:"host"`
	KekKeyID     string `mapstructure:"kek-id"`
	LogFormat    string `mapstructure:"log-format"`
	LogLevel     string `mapstructure:"log-level"`
	NativePath   string `mapstructure:"native-path"`
	P11Label     string `mapstructure:"p11-label"`
	P11Lib       string `mapstructure:"p11-lib"`
	P11Pin       string `mapstructure:"p11-pin"`
	P11Slot      int    `mapstructure:"p11-slot"`
	Port         int64  `mapstructure:"port"`
	Provider     string `mapstructure:"provider"`
	SocketPath   string `mapstructure:"socket"`
}

// Initialize the ViperConfig struct with all the root CLI flags bound to Viper env vars
var vprCfg ViperConfig

// cobra root CLI flags default value
const (
	defaultKekId = "a37807cd-6d1a-4d75-813a-e120f30176f7"
	defaultCaId  = "1c3d30d5-dfa8-4167-a9f9-2c768464181b"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "k8s-kms-plugin",
	Short: "Thales KMS Server for K8S",
	Long:  "Use this to connect a kubernetes cluster to a PKCS11 TPM or HSM.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Set logs format
		switch vprCfg.LogFormat {
		case "json":
			logrus.SetFormatter(&logrus.JSONFormatter{
				PrettyPrint: false,
			})
		case "text":
			logrus.SetFormatter(&logrus.TextFormatter{
				ForceColors:      true,
				DisableTimestamp: true,
			})
		default:
			return errors.New("logrus unknown output format")
		}
		logrus.Debugf("logrus output format is set to: %s", vprCfg.LogFormat)

		// Initialize logrus log level and log format for all cobra commands and subcommands.
		debugFlagIsUsed := cmd.Flags().Lookup("debug").Changed

		switch {
		case debugFlagIsUsed:
			// harcode that the --debug flags set logrus level to debug
			logrus.SetLevel(logrus.DebugLevel)
		default:
			// get the log level from viper which is bind to the cobra flag --log-level
			level, err := logrus.ParseLevel(vprCfg.LogLevel)
			if err != nil {
				return err
			}
			logrus.SetLevel(level)
		}
		logrus.Debugf("logrus log-level is set to: %s", logrus.GetLevel())

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
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "ConfigFile")

	// logging level
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Set logrus.SetLevel to \"debug\". This is equivalent to using --log-level=debug. Flags --log-level and --debug flag are mutually exclusive. Corresponding environment variable: K8S_KMS_PLUGIN_DEBUG.")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Set logrus.SetLevel. Possible values: trace, debug, info, warning, error, fatal and panic. Flags --log-level and --debug flag are mutually exclusive. Corresponding environment variable: K8S_KMS_PLUGIN_LOG_LEVEL.")
	rootCmd.RegisterFlagCompletionFunc("log-level", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"trace", "debug", "info", "warning", "error", "fatal", "panic"}, cobra.ShellCompDirectiveNoFileComp
	})
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "text", "Logrus log output format. Possible values: text, json. Corresponding environment variable: K8S_KMS_PLUGIN_LOG_FORMAT")
	rootCmd.RegisterFlagCompletionFunc("log-format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"text", "json"}, cobra.ShellCompDirectiveNoFileComp
	})
	rootCmd.MarkFlagsMutuallyExclusive("log-level", "debug")

	rootCmd.PersistentFlags().StringVar(&host, "host", "0.0.0.0", "Hostname without port. Corresponding environment variable: K8S_KMS_PLUGIN_HOST.")
	rootCmd.PersistentFlags().Int64Var(&grpcPort, "port", 31400, "TCP Port for gRPC service. Corresponding environment variable: K8S_KMS_PLUGIN_PORT.")
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Corresponding environment variable: K8S_KMS_PLUGIN_SOCKET")
	// Provider
	rootCmd.PersistentFlags().StringVar(&provider, "provider", "p11", "Provider. Possible values: p11, softhsm, luna, dpod. Corresponding environment variable: K8S_KMS_PLUGIN_PROVIDER.")
	rootCmd.RegisterFlagCompletionFunc("provider", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"p11", "softhsm", "luna", "dpod"}, cobra.ShellCompDirectiveNoFileComp
	})
	rootCmd.PersistentFlags().StringVar(&kekKeyId, "kek-id", defaultKekId, "Key ID for KMS KEK. Corresponding environment variable: K8S_KMS_PLUGIN_KEK_ID")
	rootCmd.PersistentFlags().StringVar(&caId, "ca-id", defaultCaId, "Cert ID for CA Cert record. Corresponding environment variable: K8S_KMS_PLUGIN_CA_ID")
	rootCmd.PersistentFlags().StringVar(&p11lib, "p11-lib", "", "Path to p11 library/client. Corresponding environment variable: K8S_KMS_PLUGIN_P11_LIBRARY")
	rootCmd.PersistentFlags().StringVar(&p11label, "p11-label", "", "P11 token label. Corresponding environment variable: K8S_KMS_PLUGIN_P11_TOKEN")
	rootCmd.PersistentFlags().IntVar(&p11slot, "p11-slot", 0, "P11 token slot. Corresponding environment variable: K8S_KMS_PLUGIN_P11_SLOT")
	rootCmd.PersistentFlags().StringVar(&p11pin, "p11-pin", "", "P11 Pin. Corresponding environment variable: K8S_KMS_PLUGIN_P11_PIN")
	rootCmd.PersistentFlags().StringVar(&dekKeyLabelName, "p11-key-label", "k8s-dek", "Key Label to use for encrypt/decrypt. Corresponding environment variable: K8S_KMS_PLUGIN_P11_KEY_LABEL.")
	rootCmd.PersistentFlags().StringVar(&hmacKeyName, "p11-hmac-label", "k8s-hmac", "Key Label to use for sha based verifications. Corresponding environment variable: K8S_KMS_PLUGIN_P11_HMAC_LABEL.")
	rootCmd.PersistentFlags().StringVarP(&nativePath, "native-path", "p", ".keys", "Path to key store for native provider(Files only). Corresponding environment variable: K8S_KMS_PLUGIN_NATIVE_PATH.")
	rootCmd.PersistentFlags().BoolVar(&createKey, "auto-create", false, "Auto create the keys if needed. Corresponding environment variable: K8S_KMS_PLUGIN_AUTO_CREATE.")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// use a configuration file parsed by viper
	switch envVar, ok := os.LookupEnv("K8S_KMS_PLUGIN_CONFIG"); {
	case rootCmd.Flags().Lookup("config").Changed && cfgFile != "":
		logrus.Tracef("Using config file from the flag: %s", cfgFile)
		viper.SetConfigFile(cfgFile)
	case ok:
		logrus.Tracef("Using config file from the environment variable: %s", envVar)
		viper.SetConfigFile(envVar)
	default:
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		logrus.Tracef("Search config in home directory %s with name \".k8ms\" (without extension).", home)
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName(".k8s-kms-plugin")
	}

	// If a config file is not found, log a fatal error. Otherwise, read it in.
	if err := viper.ReadInConfig(); err != nil {
		logrus.Fatalf("Failed to read config file: %v", err)
	} else {
		logrus.Infof("Using config file: %s", viper.ConfigFileUsed())
	}

	// Support ENV variables with prefix with viper bound to cobra
	// Example: A CLI flag like --some-flag becomes K8S_KMS_PLUGIN_SOME_FLAG in environment variables.
	viper.SetEnvPrefix("K8S_KMS_PLUGIN")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_")) // Converts flags to ENV format
	viper.AutomaticEnv()                                   // Enables automatic binding

	// Bind CLI flags to Viper (after reading config file)
	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		// Bind only if flag is explicitly set by the user
		if f.Changed {
			logrus.Debugf("Binding CLI flag: %s", f.Name)
			viper.BindPFlag(f.Name, f)
		}
	})

	// Initialize and Load the ViperConfig that are bound to cobra CLI flags
	if err := viper.Unmarshal(&vprCfg); err != nil {
		logrus.Fatalf("Failed to load config: %v", err)
	}
}
