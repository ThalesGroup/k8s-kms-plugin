/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// UnmarshalSubMergedE is a temporary fix to a flaw in viper.Sub("section") that ignores the flag/env/default/override
// priority chain when using viper.Unmarshal(). It merges the subsection of the config file back into the Viper config
// layer (without overriding) and then calls viper.Unmarshal() to take into account the flag/env/default/override
// priority chain.
//
// Parameters:
//   - v: the viper instance that contains the configuration
//   - section: the subsection of the config file to merge
//   - target: the struct to unmarshal the merged configuration into
//
// It will return an error if:
//   - the subsection does not exist in the config file
//   - the merge into the Viper config layer fails
//
// The purpose of UnmarshalSubMergedE is to temporarily fix a flaw in viper.Sub("section") from here
// https://github.com/spf13/viper/blob/9568cfcfd660a1c1c6c762f335ae79f370488417/viper.go#L764
//
// When using viper.Sub(), the resulting Viper instance only sees the config file data for that
// subsection and completely loses the flag/env/default/override priority chain.
// This is by design in Viper: viper.Sub("key") creates a new *Viper instance with its config set
// to the sub-map, but it does not inherit:
//   - overrides (v.override)
//   - environment bindings (v.env)
//   - bound flags (v.pflags)
//   - default values (v.defaults)
//
// However, viper.Unmarshal() still uses the priority chain. So using viper.Sub().Unmarshal()
// will not take into account the flag/env/default/override priority chain, since the viper.Sub()
// instance only sees the config file data for that subsection.
//
// UnmarshalSubMergedE fixes this issue by merging the config file data for the subsection into the
// Viper config layer, so that viper.Unmarshal() will use the flag/env/default/override priority chain.
//
// TODO: make a pull request to viper to fix this flaw.
func UnmarshalSubMergedE(v *viper.Viper, section string, target any) error {
	// 1. Skip if no config file is loaded at all
	if v.ConfigFileUsed() == "" {
		logrus.Trace("UnmarshalSubMerged: no config file loaded")
		return v.Unmarshal(target) // only env, flags, defaults
	}

	// 2. Extract the subsection of the config file
	sub := v.GetStringMap(section)
	if len(sub) == 0 {
		// No subsection found, fallback to flags/env/default
		logrus.Tracef("UnmarshalSubMerged: no config found for section '%s'", section)
		return v.Unmarshal(target)
	}

	// 3. Merge section into Viper's config layer (not override!)
	if err := v.MergeConfigMap(sub); err != nil {
		logrus.WithError(err).Errorf("UnmarshalSubMerged: failed to merge config section '%s'", section)
		return fmt.Errorf("failed to merge config section '%s': %w", section, err)
	}

	// 4. Now unmarshal with proper priority:
	// flags > env > merged config > defaults
	return v.Unmarshal(target)
}

// InitViperSubCmdE initializes Viper for a specific Cobra subcommand.
// It sets up the environment variable prefix using the full command path
// of the subcommand, with each command path segment separated by an underscore.
// It then binds the subcommand-specific flags to Viper. Finally, it merges
// the configuration from the subcommand's section in the config file into
// Viper's configuration, allowing it to respect the usual priority chain of
// flags > env variables > config file > defaults.
//
// Parameters:
//   - v: the Viper instance for managing configuration.
//   - cobraCmd: the Cobra command representing the subcommand.
//   - target: the structure to unmarshal the final configuration into.
//
// Returns an error if there is a failure in binding flags or unmarshalling
// the configuration.
func InitViperSubCmdE(v *viper.Viper, cobraCmd *cobra.Command, target any) error {
	// the name of the cobra subcommand is the "section" of the config file
	// in this situation we suppose the cobra command correspond to a first level command. But if it is a second or third or greater level subcommand, we need the section to represent all the parent name. How can we get the fulle path to root command ?
	logrus.WithField("cobra-cmd", cobraCmd.Use).Trace("cobra command path: " + cobraCmd.CommandPath())

	// cobra.CommandPath returns the full path to the command, including all parent commands, each command separated by 1 space.
	// TODO: allow cobra.CommandPath to get new separator like ".".
	// See https://github.com/spf13/cobra/blob/40b5bc1437a564fc795d388b23835e84f54cd1d1/command.go#L1460
	sectionPath := strings.ReplaceAll(cobraCmd.CommandPath(), " ", ".")
	logrus.WithField("cobra-cmd", cobraCmd.Use).Tracef("section path: %s", sectionPath)

	// modify viper env prefix with the current cobra subcommand name
	sectionEnvPrefix := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(sectionPath)) // for the env prefix, this should be uppercase snake case and replace dot . with underscore
	// concat the previous viper env prefix with the current cobra subcommand name
	logrus.WithField("cobra-cmd", cobraCmd.Use).Trace("new viper env prefix: " + sectionEnvPrefix)
	v.SetEnvPrefix(sectionEnvPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_")) // Converts flags to ENV format
	v.AutomaticEnv()                                   // Enables automatic binding

	// Bind subcommand-specific cobra flags to viper
	err := v.BindPFlags(cobraCmd.Flags())
	if err != nil {
		logrus.WithField("cobra-cmd", cobraCmd.Use).Errorf("error binding flags: %v", err)
		return fmt.Errorf("error binding flags: %w", err)
	}

	// Load config values for this subcommand
	err = UnmarshalSubMergedE(v, sectionPath, &target)
	if err != nil {
		logrus.WithField("cobra-cmd", cobraCmd.Use).Fatalf("failed to unmarshal version config: %v", err)
		return fmt.Errorf("failed to unmarshal version config: %w", err)
	}

	// Synchronize Cobra flags with Viper configuration to support cobra's
	// MarkFlagsMutuallyExclusive and MarkFlagsOneRequired.
	// Source : https://github.com/spf13/viper/pull/852/files
	// Without this, if a cobra flag is marked MarkFlagsMutuallyExclusive or MarkFlagsOneRequired,
	// when a user decide to use a config file or an env variable rather than the CLI flag itself
	// to set the value of this flag, cobra will not be aware that the value is set through viper.
	// In this situation, cobra will give an error even is viper set the value.
	cobraCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if viper.IsSet(f.Name) && viper.GetString(f.Name) != "" {
			cobraCmd.Flags().Set(f.Name, viper.GetString(f.Name))
		}
	})

	return nil
}

// ReadViperConfigE reads a viper configuration file from a variety of sources.
//
// If the "-c" or "--config" flag is set, it reads from the file specified by
// that flag. If that flag is not set, it looks for an environment variable
// named K8S_KMS_PLUGIN_CONFIG and reads the file specified by that variable.
// If neither the flag nor the environment variable is set, it looks for a
// file named "k8s-kms-plugin.conf.yaml" in the following places, in order:
// - The user's home directory (e.g. ~/.config/k8s-kms-plugin.conf.yaml)
// - The .config directory under the user's home directory (e.g. ~/.config/k8s-kms-plugin.conf.yaml)
//
// If a config file is not found, it logs a trace error and continues with
// cobra's default values. Otherwise, it reads in the config file and returns
// an error if there was a problem doing so.
func ReadViperConfigE(v *viper.Viper, cmd *cobra.Command) error {
	// use a configuration file parsed by viper
	if cmd.Flags().Lookup("config").Changed && cfgFile != "" {
		logrus.Tracef("Case config file from the flag: %s", cfgFile)
		viper.SetConfigFile(cfgFile)
	} else if envVar, ok := os.LookupEnv("K8S_KMS_PLUGIN_CONFIG"); ok {
		logrus.Tracef("Case config file from the environment variable: %s", envVar)
		viper.SetConfigFile(envVar)
	} else {
		logrus.Tracef("Case config file from default location")
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			return fmt.Errorf("failed to find home directory: %w", err)
		}

		viper.SetConfigName("k8s-kms-plugin.conf") // name of config file (viper needs no file extension)
		// TODO: consider using the rootCmd.Flags().Lookup("config").DefValue for viper.SetConfigName
		// logrus.Infof("default config filename %s", rootCmd.Flags().Lookup("config").DefValue)
		logrus.Tracef("Search config in .config directory %s with name k8s-kms-plugin.conf.yaml (without extension).", home)
		viper.AddConfigPath(home)
		logrus.Tracef("Search config in home directory %s with name k8s-kms-plugin.conf.yaml (without extension).", filepath.Join(home, ".config/k8s-kms-plugin"))
		viper.AddConfigPath(filepath.Join(home, ".config/k8s-kms-plugin"))
	}

	// If a config file is not found, log a trace error. Otherwise, read it in.
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logrus.Trace("No config file found; continue with cobra default values")
		} else {
			// Config file was found but another error occurred
			return fmt.Errorf("error reading config file: %w", err)
		}
	}
	return nil
}
