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
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/k8s-kms-plugin/pkg/providers"
	"github.com/ThalesGroup/k8s-kms-plugin/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	k8skmsv2 "k8s.io/kms/apis/v2"
)

// ViperFlagsRotation defines a struct to hold the values of cobra CLI flags and use viper to populate them
// These are the parameters of the KEK key that is being rotated which means it is the old KEK.
// Use ViperFlagsServe for the current new KEK.
type ViperFlagsRotation struct {
	// PKCS #11 & KMS plugin parameters
	OldAlgorithm  string `mapstructure:"old-algorithm"`
	OldCaID       string `mapstructure:"old-ca-id"`
	OldCaTLSCert  string `mapstructure:"old-tls-ca"`
	OldNativePath string `mapstructure:"old-native-path"`
	OldP11Label   string `mapstructure:"old-p11-label"`
	OldP11Lib     string `mapstructure:"old-p11-lib"`
	OldP11Pin     string `mapstructure:"old-p11-pin"`
	OldP11Slot    int    `mapstructure:"old-p11-slot"`
	OldProvider   string `mapstructure:"old-provider"`
	OldSocketPath string `mapstructure:"old-socket"` // Unix socket path for TPM or HSM

	// CKA_ID and CKA_LABEL
	OldDekKeyLabel  string `mapstructure:"old-p11-key-label"`
	OldHmacKeyID    string `mapstructure:"old-p11-hmac-id"`
	OldHmacKeyLabel string `mapstructure:"old-p11-hmac-label"`
	OldKekKeyID     string `mapstructure:"old-p11-key-id"`
}

// Declare the viper CLI flag values buffer
var vprFlgsRotation ViperFlagsRotation

// rotationCmd represents the keyRotation command
var rotationCmd = &cobra.Command{
	Use:   "rotation",
	Short: "KEK Key rotation for KMS v2",
	Long: `Handles Kubernetes KMS v2 requests and support KEK key rotation with x1 old KEK key and x1 active KEK key.
"k8s-kms-pluginc serve rotation" is very similar to the "k8s-kms-plugin serve" command, but adds key rotation support.
Refer to the kubernetes KMS v2 documentation for more details about key rotation.
https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#developing-a-kms-plugin-gRPC-server-notes-kms-v2

KMS v2 API: https://pkg.go.dev/k8s.io/kms@v0.34.1/apis/v2
`,
	Example: `
Using flags and serving on unix socket (gRPC plaintext):
	k8s-kms-plugin \
	  serve \
		--log-level=trace \
		--socket /run/user/1000/k8s-kms-plugin.sock \
		--p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
		--p11-label mylabel \
		--p11-pin mypin \
		--p11-key-label rsa0 \
		--algorithm rsa-oaep \
		  rotation \
			--old-p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
			--old-p11-label mylabel \
			--old-p11-pin mypin \
			--old-p11-key-id 64636138353931326363356537313264 \
			--old-p11-hmac-id 30663536623936326235663530363234 \
			--old-algorithm aes-cbc

Using environment variables and configuration file:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin serve rotation --config my-kms-plugin-config.yaml

Using both CLI Flags, environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin --log-format=json serve rotation --config my-kms-plugin-config.yaml
	`,
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Manually call parent’s PersistentPreRunE
		if cmd.Parent() != nil && cmd.Parent().PersistentPreRunE != nil {
			if err := cmd.Parent().PersistentPreRunE(cmd.Parent(), args); err != nil {
				return err
			}
		}

		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsRotation); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Error("Error initializing Viper")
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// Show the version of the k8s-kms-plugin and commit ID
		version.LogrusOutputVersion()

		// provider for the KEK that is being rotated, aka the old KEK
		var p providers.Provider

		p, err = initRotatedProvider()
		if err != nil && providers.IsPKCS11AuthenticationError(err) {
			// Don't panic/exit if we have a PKCS#11 error.
			// Sleep forever instead.
			logrus.WithField("cobra-cmd", cmd.Use).
				WithError(err).
				Error("PKCS11 authentication error detected. Further retries may cause the token to be erased.")
			logrus.WithField("cobra-cmd", cmd.Use).Warn("Process will now sleep indefinitely to prevent further damage...")
			time.Sleep(8760 * time.Hour)
		}

		if err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Fatal("failed to initialize rotated provider for old KEK")
		}

		if err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Fatal("failed to initialize provider for new KEK")
		}

		// gRPC server
		g := new(errgroup.Group)
		var grpcTCP, grpcUNIX net.Listener

		if vprFlgsServe.EnableTCP {
			// vprFlgsServe.Port needs to be converted from uint16 to string
			grpcAddr := net.JoinHostPort(vprFlgsServe.Host, strconv.FormatUint(uint64(vprFlgsServe.Port), 10))

			if grpcTCP, err = net.Listen("tcp", grpcAddr); err != nil {
				return
			}

			g.Go(func() error { return grpcRotation(grpcTCP, p) })
		}

		if !vprFlgsServe.DisableSocket {
			_ = os.Remove(vprFlgsServe.SocketPath)
			if grpcUNIX, err = net.Listen("unix", vprFlgsServe.SocketPath); err != nil {
				return
			}

			// Istiod runs with uid and gid 1337, but the plugin runs with uid 0 and
			// gid 1337.  Change the socket permissions so the group has read/write
			// access to the socket.
			os.Chmod(vprFlgsServe.SocketPath, 0775)
			g.Go(func() error { return grpcRotation(grpcUNIX, p) })
		}

		if err = g.Wait(); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).Error(err)
		}

		return nil
	},
}

func init() {
	serveCmd.AddCommand(rotationCmd)

	rotationCmd.Flags().String("old-algorithm", "", "Set the algorithm for the old KEK")
	rotationCmd.Flags().String("old-ca-id", "", "Cert ID for old CA Cert record")
	rotationCmd.Flags().String("old-tls-ca", "", "TLS CA cert for old KEK")
	rotationCmd.Flags().String("old-native-path", "", "Native path for old KEK")
	rotationCmd.Flags().String("old-p11-label", "", "P11 token label for old KEK")
	rotationCmd.Flags().String("old-p11-lib", "", "Path to P11 library/client for old KEK")
	rotationCmd.Flags().String("old-p11-pin", "", "P11 Pin for old KEK")

	rotationCmd.Flags().Int("old-p11-slot", 0, "P11 token slot for old KEK")
	rotationCmd.Flags().String("old-provider", "p11", "Provider for old KEK")
	rotationCmd.Flags().String("old-socket", "", "Unix socket path for old KEK")
	rotationCmd.Flags().String("old-p11-key-label", "", "Key Label CKA_LABEL for old KEK")
	rotationCmd.Flags().String("old-p11-hmac-id", "", "Key ID CKA_ID for old KEK HMAC")
	rotationCmd.Flags().String("old-p11-hmac-label", "", "Key Label CKA_LABEL for old KEK HMAC")
	rotationCmd.Flags().String("old-p11-key-id", "", "Key ID CKA_ID for old KEK")

	// At least one of the old KEK CKA_ID or old CKA_LABEL must be provided by the user
	rotationCmd.MarkFlagsOneRequired("old-p11-key-id", "old-p11-key-label")

	// To prevent mismatch between user provided CKA_ID and user provided CKA_LABEL, flags are Mutually Exclusive.
	// NewP11 make sure to retrieve the ID by label, or label by ID.
	rotationCmd.MarkFlagsMutuallyExclusive("old-p11-key-id", "old-p11-key-label")
	rotationCmd.MarkFlagsMutuallyExclusive("old-p11-hmac-id", "old-p11-hmac-label")
}

func initRotatedProvider() (pRot providers.Provider, err error) {
	// Active key
	// init the algorithm to use in the kms from user input
	activeAlg, err := algFromString(vprFlgsServe.Algorithm)
	if err != nil {
		return
	}

	// init the provider activeConfig from user input
	activeConfig := &crypto11.Config{}
	switch vprFlgsServe.Provider {
	case "p11", "softhsm":
		logrus.Debug("initProvider: case p11 or softhsm")
		activeConfig = &crypto11.Config{
			Path:            vprFlgsServe.P11Lib,
			Pin:             vprFlgsServe.P11Pin,
			UseGCMIVFromHSM: false,
		}

	case "luna", "dpod":
		logrus.Debug("initProvider: case luna HSM or dpod")
		activeConfig = &crypto11.Config{
			Path:            vprFlgsServe.P11Lib,
			Pin:             vprFlgsServe.P11Pin,
			UseGCMIVFromHSM: true,
			GCMIVFromHSMControl: crypto11.GCMIVFromHSMConfig{
				SupplyIvForHSMGCMEncrypt: false,
				SupplyIvForHSMGCMDecrypt: true,
			},
		}
	default:
		logrus.WithField("provider", vprFlgsServe.Provider).Error("unknown provider")
		err = errors.New("unknown provider")
		return
	}

	if vprFlgsServe.P11Label != "" {
		activeConfig.TokenLabel = vprFlgsServe.P11Label
	} else {
		activeConfig.SlotNumber = &vprFlgsServe.P11Slot
	}

	// Rotated old key
	// init the algorithm to use in the kms from user input
	rotatedAlg, err := algFromString(vprFlgsRotation.OldAlgorithm)
	if err != nil {
		return
	}

	// init the provider oldConfig from user input
	oldConfig := &crypto11.Config{}
	switch vprFlgsRotation.OldProvider {
	case "p11", "softhsm":
		logrus.Debug("initProvider: case p11 or softhsm")
		oldConfig = &crypto11.Config{
			Path:            vprFlgsRotation.OldP11Lib,
			Pin:             vprFlgsRotation.OldP11Pin,
			UseGCMIVFromHSM: false,
		}

	case "luna", "dpod":
		logrus.Debug("initProvider: case luna HSM or dpod")
		oldConfig = &crypto11.Config{
			Path:            vprFlgsRotation.OldP11Lib,
			Pin:             vprFlgsRotation.OldP11Pin,
			UseGCMIVFromHSM: true,
			GCMIVFromHSMControl: crypto11.GCMIVFromHSMConfig{
				SupplyIvForHSMGCMEncrypt: false,
				SupplyIvForHSMGCMDecrypt: true,
			},
		}
	default:
		logrus.WithField("provider", vprFlgsRotation.OldProvider).Error("unknown provider")
		err = errors.New("unknown provider")
		return
	}

	if vprFlgsRotation.OldP11Label != "" {
		oldConfig.TokenLabel = vprFlgsRotation.OldP11Label
	} else {
		oldConfig.SlotNumber = &vprFlgsRotation.OldP11Slot
	}
	// init the provider
	// TODO: See https://github.com/ThalesGroup/k8s-kms-plugin/issues/40#issuecomment-2593267852
	if pRot, err = providers.NewP11(
		oldConfig,
		vprFlgsServe.CreateKey,
		vprFlgsServe.KekKeyID,
		vprFlgsServe.DekKeyLabel,
		vprFlgsServe.HmacKeyLabel,
		vprFlgsServe.HmacKeyID,
		activeAlg,
		true, // key rotation
		oldConfig,
		vprFlgsRotation.OldKekKeyID,
		vprFlgsRotation.OldDekKeyLabel,
		vprFlgsRotation.OldHmacKeyLabel,
		vprFlgsRotation.OldHmacKeyID,
		rotatedAlg,
	); err != nil {
		return
	}
	return
}

func grpcRotation(gl net.Listener, p providers.Provider) (err error) {
	logrus.Trace("grpcRotation")

	// Create a gRPC server to host the services
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(p.UnaryInterceptor),
		grpc.UnknownServiceHandler(unknownServiceHandler),
	}
	gs := grpc.NewServer(serverOptions...)

	k8skmsv2.RegisterKeyManagementServiceServer(gs, p)
	reflection.Register(gs)

	logrus.Infof("Serving on socket: %s", gl.Addr().String())
	logrus.Debugf("grpcRotation: value of grpcPort user input: %d", vprFlgsServe.Port)

START:
	if err = gs.Serve(gl); err != nil {
		logrus.Error(err)
		goto START
	}
	return
}
