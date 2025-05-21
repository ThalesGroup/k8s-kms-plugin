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
	"time"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ViperFlagsGenerateKEK defines a struct to hold the values of cobra CLI flags and use viper to populate them
type ViperFlagsGenerateKEK struct {
	KekKeyID string `mapstructure:"kek-id"`

	Socket  string        `mapstructure:"socket"`
	Timeout time.Duration `mapstructure:"timeout"`
}

// Declare the viper CLI flag values buffer
var vprFlgsGenerateKEK ViperFlagsGenerateKEK

var generateKEKCmd = &cobra.Command{
	Use:     "generate-kek",
	Short:   "Generate a KEK",
	GroupID: "kmscmdsgrpsupporting",
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsGenerateKEK); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Error("Error initializing Viper")
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := generateKEK(); err != nil {
			return err
		}
		return nil
	},
}

// generateKEK sends a GenerateKEKRequest to the KMS and prints the generated KEK ID
// Inputs:
//   - KMS socket path
//   - KMS timeout
//   - KMS KEK ID
func generateKEK() error {
	ctx, cancel, c, err := istio.GetClientSocket(vprFlgsGenerateKEK.Socket, vprFlgsGenerateKEK.Timeout)
	defer cancel()
	if err != nil {
		return fmt.Errorf("could not open socket: %v", err)
	}

	genKEKResp, err := c.GenerateKEK(ctx, &istio.GenerateKEKRequest{
		KekKid: []byte(vprFlgsGenerateKEK.KekKeyID),
	})
	if err != nil {
		return fmt.Errorf("generate KEK failed: %v", err)
	}
	fmt.Println("KEK ID:", string(genKEKResp.KekKid))

	return nil
}

func init() {
	rootCmd.AddCommand(generateKEKCmd)

	// Since this project uses Viper bind with Cobra flags, we generally do not need to use "Flags().*Var"
	// (like StringVar, BoolVar, Uint16Var, etc...) as we do not need to access the cobra flag values directly. This is
	// because we use Viper to retrieve the values of the flags.
	generateKEKCmd.Flags().String("kek-id", defaultKekId, "Key ID for KMS KEK. Env var: K8S_KMS_PLUGIN_GENERATE_KEK_KEK_ID")

	// Socket & Timeout
	generateKEKCmd.Flags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_GENERATE_KEK_SOCKET")
	generateKEKCmd.Flags().Duration("timeout", 30*time.Second, "KMS timeout. Env var: K8S_KMS_PLUGIN_GENERATE_KEK_TIMEOUT")
}
