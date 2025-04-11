// MIT License
//
// Copyright (c) 2025 Thales. All rights reserved.
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
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Parameters:
//   - v: the viper instance that contains the configuration
//   - section: the subsection of the config file to merge
//   - target: the struct to unmarshal the merged configuration into
//
// The purpose of UnmarshalSubMerged is to temporarily fix a flaw in viper.Sub("section") from here
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
// UnmarshalSubMerged fixes this issue by merging the config file data for the subsection into the
// Viper config layer, so that viper.Unmarshal() will use the flag/env/default/override priority chain.
//
// TODO: make a pull request to viper to fix this flaw.
func UnmarshalSubMerged(v *viper.Viper, section string, target any) error {
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

// initViper binds cobra flags to viper for the given subcommand and unmarshals
// the configuration into the specified target. It first binds the flags of the
// provided cobra command to viper, logging and exiting on error. Then, it attempts
// to unmarshal the merged configuration data, which includes flag, environment,
// and default values, into the target. Logs fatal on unmarshalling failure.
func InitViperSubCmd(v *viper.Viper, cobraCmd *cobra.Command, target any) {
	// the name of the cobra subcommand is the "section" of the config file
	// in this situation we suppose the cobra command correspond to a first level command. But if it is a second or third or greater level subcommand, we need the section to represent all the parent name. How can we get the fulle path to root command ?
	var path []string
	for cmd := cobraCmd; cmd != nil && cmd.HasParent(); cmd = cmd.Parent() {
		path = append([]string{cmd.Name()}, path...)
	}
	section := strings.Join(path, ".") // for parsing the config file

	// modify viper env prefix with the current cobra subcommand name
	envPrefixSubCmd := strings.ToUpper(strings.Join(path, "_"))
	envPrefixSubCmd = strings.ReplaceAll(envPrefixSubCmd, "-", "_")
	v.SetEnvPrefix(strings.Join([]string{v.GetEnvPrefix(), envPrefixSubCmd}, "_"))

	// Bind subcommand-specific cobra flags to viper
	err := v.BindPFlags(cobraCmd.Flags())
	if err != nil {
		logrus.WithField("cobra-cmd", cobraCmd.Use).Errorf("error binding flags: %v", err)
		os.Exit(1)
	}

	err = UnmarshalSubMerged(v, section, &target)
	if err != nil {
		logrus.Fatalf("failed to unmarshal version config: %v", err)
	}
}
