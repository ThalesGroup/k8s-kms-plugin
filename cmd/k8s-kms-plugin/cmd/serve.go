/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package cmd

// TODO replace github imports for :
//   - gose
//   - crypto11
import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/jose"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	version "github.com/ThalesGroup/k8s-kms-plugin/pkg/version"
	k8skmsv2 "k8s.io/kms/apis/v2"

	"github.com/ThalesGroup/k8s-kms-plugin/pkg/providers"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// ViperFlagsServe defines a struct to hold the values of cobra CLI flags and use viper to populate them
type ViperFlagsServe struct {
	// gRPC server parameters
	AllowAny      bool   `mapstructure:"allow-any"`
	DisableSocket bool   `mapstructure:"disable-socket"`
	EnableTCP     bool   `mapstructure:"enable-server"`
	Host          string `mapstructure:"host"`
	Port          uint16 `mapstructure:"port"`
	ServerTLSCert string `mapstructure:"tls-certificate"`
	ServerTLSKey  string `mapstructure:"tls-key"`
	CaTLSCert     string `mapstructure:"tls-ca"`

	// PKCS #11 & KMS plugin parameters
	Algorithm  string `mapstructure:"algorithm"`
	CaID       string `mapstructure:"ca-id"`
	NativePath string `mapstructure:"native-path"`
	P11Label   string `mapstructure:"p11-label"`
	P11Lib     string `mapstructure:"p11-lib"`
	P11Pin     string `mapstructure:"p11-pin"`
	P11Slot    int    `mapstructure:"p11-slot"`
	Provider   string `mapstructure:"provider"`
	SocketPath string `mapstructure:"socket"` // Unix socket path for TPM or HSM

	// PKCS #11 CKA_ID and CKA_LABEL of active KEK key
	CreateKey    bool   `mapstructure:"auto-create"`
	DekKeyLabel  string `mapstructure:"p11-key-label"`  // active DEK key CKA_LABEL
	HmacKeyID    string `mapstructure:"p11-hmac-id"`    // active HMAC key CKA_ID
	HmacKeyLabel string `mapstructure:"p11-hmac-label"` // active HMAC key CKA_LABEL
	KekKeyID     string `mapstructure:"p11-key-id"`     // active KEK key CKA_ID
}

// Declare the viper CLI flag values buffer
var vprFlgsServe ViperFlagsServe

// Algorithm supports user input for configuration
type Algorithm struct {
	slug string
}

var (
	UNKNOWNALG = Algorithm{""}
	AESGCM     = Algorithm{"aes-gcm"}
	AESCBC     = Algorithm{"aes-cbc"}
	RSAOAEP    = Algorithm{"rsa-oaep"}
)

func algFromString(s string) (jose.Alg, error) {
	switch s {
	case AESGCM.slug:
		return jose.AlgA256GCM, nil
	case AESCBC.slug:
		return jose.AlgA256CBC, nil
	case RSAOAEP.slug:
		return jose.AlgRSAOAEP, nil
	default:
		return "", gose.ErrInvalidAlgorithm
	}
}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Handles Kubernetes KMS v2 requests",
	Long: `Handles Kubernetes KMS v2 requests but do not support key rotation.
Use "k8s-kms-plugin serve rotation" subcommand to support key rotation.
Kubernetes KMS documentation: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#configuring-the-kms-provider-kms-v2

KMS v2 API: https://pkg.go.dev/k8s.io/kms@v0.34.1/apis/v2
`,
	Example: `
Using flags and serving on unix socket (gRPC plaintext):
	k8s-kms-plugin 
	  serve \
		--log-level=info \
		--socket /run/user/1000/k8s-kms-plugin.sock \
		--p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
		--p11-label mylabel \
		--p11-pin mypin \
		--p11-key-label rsa0 \
		--algorithm rsa-oaep

Using both environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin serve --config my-kms-plugin-config.yaml

Using both CLI Flags, environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin --log-format=json serve --config my-kms-plugin-config.yaml

Using AES-CBC with HMAC authentication, using CKA_ID, using CLI flags and serving on unix socket:
	k8s-kms-plugin 
	  serve \
		--log-level=trace  \
		--socket /run/user/1000/k8s-kms-plugin.sock \
		--p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
		--p11-label mylabel \
		--p11-pin mypin \
		--p11-key-id 64636138353931326363356537313264 \
		--p11-hmac-id 30663536623936326235663530363234 \
		--algorithm aes-cbc
`,
	GroupID: "kmscmdsgrpmain",
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsServe); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Error("Error initializing Viper")
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// Show the version of the k8s-kms-plugin and commit ID
		version.LogrusOutputVersion()

		// Don't panic/exit if we have a PKCS#11 error.
		// Sleep forever instead.
		var p providers.Provider
		p, err = initProvider()
		if err != nil && providers.IsPKCS11AuthenticationError(err) {
			logrus.WithField("cobra-cmd", cmd.Use).
				WithError(err).
				Error("PKCS11 authentication error detected. Further retries may cause the token to be erased.")
			logrus.WithField("cobra-cmd", cmd.Use).Warn("Process will now sleep indefinitely to prevent further damage...")
			time.Sleep(8760 * time.Hour)
		}

		if err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).Fatalf("failed to initialize provider: %v", err)
		}

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

		return
	},
}

func init() {
	// rootCmd is the parent command
	rootCmd.AddCommand(serveCmd)

	// Since this project uses Viper bind with Cobra flags, we generally do not need to use "Flags().*Var"
	// (like StringVar, BoolVar, Uint16Var, etc...) as we do not need to access the cobra flag values directly. This is
	// because we use Viper to retrieve the values of the flags.

	// unix socket server options
	serveCmd.PersistentFlags().Bool("disable-socket", false, "Disable socket based server.")

	// tcp server options
	serveCmd.PersistentFlags().Bool("enable-server", false, "Enable TLS based server.")
	serveCmd.PersistentFlags().String("tls-ca", "certs/ca.crt", "TLS CA cert.")
	serveCmd.PersistentFlags().String("tls-key", "certs/tls.key", "TLS server key.")
	serveCmd.PersistentFlags().String("tls-certificate", "certs/tls.crt", "TLS server cert.")

	serveCmd.PersistentFlags().Bool("allow-any", false, "Allow any device (accepts all ids/secrets).")

	serveCmd.PersistentFlags().String("algorithm", "aes-gcm", "Set the algorithm for encryption/decryption. Possible values: aes-gcm, aes-cbc, rsa-oaep.")
	serveCmd.RegisterFlagCompletionFunc("algorithm", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"aes-gcm", "aes-cbc", "rsa-oaep"}, cobra.ShellCompDirectiveNoFileComp
	})

	// These flags comes from root
	// These flags does not need to store their values in variable because we use the viper structure ViperFlagsServe to do this
	serveCmd.PersistentFlags().String("ca-id", defaultCaId, "Cert ID for CA Cert record.")
	serveCmd.PersistentFlags().Bool("auto-create", false, "Auto create the keys if needed.")
	serveCmd.PersistentFlags().String("p11-key-label", "", "Key Label CKA_LABEL to use for encrypt/decrypt.")
	serveCmd.PersistentFlags().String("p11-hmac-label", "", "Key Label CKA_LABEL to use for sha based verifications.")
	serveCmd.PersistentFlags().String("host", "0.0.0.0", "Hostname without port.")
	serveCmd.PersistentFlags().String("p11-key-id", "", "Key ID CKA_ID for KMS KEK.")
	serveCmd.PersistentFlags().String("p11-hmac-id", "", "Key ID CKA_ID for KMS HMAC.")
	serveCmd.PersistentFlags().StringP("native-path", "p", ".keys", "Path to key store for native provider(Files only).")
	serveCmd.PersistentFlags().String("p11-label", "", "P11 token label.")
	serveCmd.PersistentFlags().String("p11-lib", "", "Path to p11 library/client.")
	serveCmd.PersistentFlags().String("p11-pin", "", "P11 Pin.")
	serveCmd.PersistentFlags().Int("p11-slot", 0, "P11 token slot.")
	serveCmd.PersistentFlags().Uint16("port", 31400, "TCP Port for gRPC service.")
	// Provider
	serveCmd.PersistentFlags().String("provider", "p11", "Provider. Possible values: p11, softhsm, luna, dpod.")
	serveCmd.RegisterFlagCompletionFunc("provider", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"p11", "softhsm", "luna", "dpod"}, cobra.ShellCompDirectiveNoFileComp
	})

	// Socket
	serveCmd.PersistentFlags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock.")

	// At least one of KEK CKA_ID or CKA_LABEL must be provided by the user
	serveCmd.MarkFlagsOneRequired("p11-key-id", "p11-key-label")

	// To prevent mismatch between user provided CKA_ID and user provided CKA_LABEL, flags are Mutually Exclusive.
	// NewP11 make sure to retrieve the ID by label, or label by ID.
	serveCmd.MarkFlagsMutuallyExclusive("p11-key-id", "p11-key-label")
	serveCmd.MarkFlagsMutuallyExclusive("p11-hmac-id", "p11-hmac-label")
}

func initProvider() (p providers.Provider, err error) {
	// init the algorithm to use in the kms from user input
	alg, err := algFromString(vprFlgsServe.Algorithm)
	if err != nil {
		return
	}

	// init the provider config from user input
	config := &crypto11.Config{}
	switch vprFlgsServe.Provider {
	case "p11", "softhsm":
		logrus.Debug("initProvider: case p11 or softhsm")
		config = &crypto11.Config{
			Path:            vprFlgsServe.P11Lib,
			Pin:             vprFlgsServe.P11Pin,
			UseGCMIVFromHSM: false,
		}

	case "luna", "dpod":
		logrus.Debug("initProvider: case luna HSM or dpod")
		config = &crypto11.Config{
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
		config.TokenLabel = vprFlgsServe.P11Label
	} else {
		config.SlotNumber = &vprFlgsServe.P11Slot
	}
	// init the provider for active key only (no key rotation)
	// TODO: See https://github.com/ThalesGroup/k8s-kms-plugin/issues/40#issuecomment-2593267852
	if p, err = providers.NewP11(
		config,
		vprFlgsServe.CreateKey,
		vprFlgsServe.KekKeyID,
		vprFlgsServe.DekKeyLabel,
		vprFlgsServe.HmacKeyLabel,
		vprFlgsServe.HmacKeyID,
		alg,
		false, // no key rotation
		nil,
		"",
		"",
		"",
		"",
		"",
	); err != nil {
		return
	}
	return
}

func grpcServe(gl net.Listener, p providers.Provider) (err error) {
	logrus.Trace("grpcServe")

	// Create a gRPC server to host the services
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(p.UnaryInterceptor),
		grpc.UnknownServiceHandler(unknownServiceHandler),
	}
	gs := grpc.NewServer(serverOptions...)

	k8skmsv2.RegisterKeyManagementServiceServer(gs, p)
	reflection.Register(gs)
	istio.RegisterKeyManagementServiceServer(gs, p)

	logrus.Infof("Serving on socket: %s", gl.Addr().String())
	logrus.Debugf("grpcServe: value of grpcPort user input: %d", vprFlgsServe.Port)

START:
	if err = gs.Serve(gl); err != nil {
		logrus.Error(err)
		goto START
	}
	return
}

func unknownServiceHandler(srv interface{}, stream grpc.ServerStream) error {
	typeOfSrv := reflect.TypeOf(srv)
	logrus.Infof("unknownServiceHandler. Looking for: %v, %v", typeOfSrv, srv)
	return nil
}
