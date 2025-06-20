/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
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
	OldHmacKeyID    string `mapstructure:"old-hmac-id"`
	OldHmacKeyLabel string `mapstructure:"old-p11-hmac-label"`
	OldKekKeyID     string `mapstructure:"old-kek-id"`
}

// Declare the viper CLI flag values buffer
var vprFlgsRotation ViperFlagsRotation

// rotationCmd represents the keyRotation command
var rotationCmd = &cobra.Command{
	Use:   "rotation",
	Short: "KEK Key rotation for KMS v2",
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsServe); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Error("Error initializing Viper")
			return err
		}
		return nil
	},
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
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

			g.Go(func() error { return grpcServe(grpcTCP, p) })
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
			g.Go(func() error { return grpcServe(grpcUNIX, p) })
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
	rotationCmd.Flags().String("old-provider", "", "Provider for old KEK")
	rotationCmd.Flags().String("old-socket", "", "Unix socket path for old KEK")
	rotationCmd.Flags().String("old-p11-key-label", "", "Key Label CKA_LABEL for old KEK")
	rotationCmd.Flags().String("old-hmac-id", "", "Key ID CKA_ID for old KEK HMAC")
	rotationCmd.Flags().String("old-p11-hmac-label", "", "Key Label CKA_LABEL for old KEK HMAC")
	rotationCmd.Flags().String("old-kek-id", "", "Key ID CKA_ID for old KEK")
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
