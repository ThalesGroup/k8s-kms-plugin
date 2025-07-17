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
	"fmt"
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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

// ViperFlagsServe defines a struct to hold the values of cobra CLI flags and use viper to populate them
type ViperFlagsServe struct {
	// gRPC server parameters
	AllowAny      bool   `mapstructure:"allow-any"`
	GrpcNetwork   string `mapstructure:"grpc-network"`
	Host          string `mapstructure:"host"`
	Port          uint16 `mapstructure:"port"`
	ServerTLSCert string `mapstructure:"tls-certificate"`
	ServerTLSKey  string `mapstructure:"tls-key"`
	CaTLSCert     string `mapstructure:"tls-ca"`
	EnableTLS     bool   `mapstructure:"enable-tls"`

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
	HmacKeyID    string `mapstructure:"hmac-id"`        // active HMAC key CKA_ID
	HmacKeyLabel string `mapstructure:"p11-hmac-label"` // active HMAC key CKA_LABEL
	KekKeyID     string `mapstructure:"kek-id"`         // active KEK key CKA_ID
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
	Long: `Handles Kubernetes KMS v2 requests without key rotation.
Use "k8s-kms-plugin serve rotation" subcommand for key rotation support.
Kubernetes documentation: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#configuring-the-kms-provider-kms-v2
`,
	Example: `
Using flags and serving on unix socket:
	k8s-kms-plugin serve \
	    --log-level=info \
	    --socket /run/user/1000/k8s-kms-plugin.sock \
	    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
	    --p11-label mylabel \
	    --p11-pin mypin \
	    --p11-key-label rsa0 \
	    --algorithm rsa-oaep

Using environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin serve rotation --config my-kms-plugin-config.yaml

	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin --log-format=json serve rotation --config my-kms-plugin-config.yaml

Serving on TCP IPv4 and enabling TLS for the gRPC API:
    k8s-kms-plugin serve  \
        --log-level=trace  \
        --p11-lib  /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1  \
        --p11-label  mylabel  \
        --p11-pin  mypin  \
        --kek-id  123abc  \
        --algorithm  rsa-oaep \
        --grpc-network tcp4 \
        --port 8842 \
        --enable-tls \
        --tls-key ~/certs/tls.key \
        --tls-certificate ~/certs/tls.crt \
        --tls-ca ~/certs/ca.crt

Using AES-CBC with HMAC authentication and serving on unix socket:
    k8s-kms-plugin serve  \
        --log-level=trace  \
        --socket /run/user/1000/k8s-kms-plugin.sock \
        --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
        --p11-label mylabel \
        --p11-pin mypin \
        --kek-id 64636138353931326363356537313264 \
        --hmac-id 30663536623936326235663530363234 \
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

		switch vprFlgsServe.GrpcNetwork {
		case "tcp", "tcp4", "tcp6":
			if cmd.Flags().Lookup("socket").Changed {
				errOut := fmt.Errorf("do not set the unix --socket flag or K8S_KMS_PLUGIN_SERVE_KEK_SOCKET when flag --grpc-network or K8S_KMS_PLUGIN_SERVE_GRPC_NETWORK is set to tcp*")
				logrus.WithField("cobra-cmd", cmd.Use).
					WithError(errOut).
					Error("wrong user cli input")
				return errOut
			}
			// vprFlgsServe.Port needs to be converted from uint16 to string
			grpcAddr := net.JoinHostPort(vprFlgsServe.Host, strconv.FormatUint(uint64(vprFlgsServe.Port), 10))

			if grpcTCP, err = net.Listen(vprFlgsServe.GrpcNetwork, grpcAddr); err != nil {
				return
			}

			g.Go(func() error { return grpcServe(grpcTCP, p) })
		case "unix":
			_ = os.Remove(vprFlgsServe.SocketPath)
			if grpcUNIX, err = net.Listen("unix", vprFlgsServe.SocketPath); err != nil {
				return
			}

			// Istiod runs with uid and gid 1337, but the plugin runs with uid 0 and
			// gid 1337.  Change the socket permissions so the group has read/write
			// access to the socket.
			os.Chmod(vprFlgsServe.SocketPath, 0775)
			g.Go(func() error { return grpcServe(grpcUNIX, p) })
		default:
			errOut := fmt.Errorf("unknown gRPC network listener type: %q", vprFlgsServe.GrpcNetwork)
			logrus.WithField("cobra-cmd", cmd.Use).
				WithError(errOut).
				Error("unknown gRPC network listener type")
			return errOut
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
	// because we use Viper and our custom Viper patch "cmd/k8s-kms-plugin/cmd/viper-patch-sub.go" to retrieve the
	// values of the flags.

	// gRPC network parameter
	serveCmd.PersistentFlags().String("grpc-network", "unix", "Network to listen on for gRPC API. Options: tcp, tcp4, tcp6, unix. Env var: K8S_KMS_PLUGIN_SERVE_GRPC_NETWORK")
	serveCmd.RegisterFlagCompletionFunc("grpc-network", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"tcp", "tcp4", "tcp6", "unix"}, cobra.ShellCompDirectiveNoFileComp
	})

	// unix socket server parameters for the kubernetes facing gRPC API
	serveCmd.PersistentFlags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_SERVE_KEK_SOCKET")

	// TCP parameters for the kubernetes facing gRPC API
	serveCmd.PersistentFlags().String("host", "0.0.0.0", "Hostname without port. Env var: K8S_KMS_PLUGIN_SERVE_HOST.")
	serveCmd.PersistentFlags().Uint16("port", 31400, "TCP Port for gRPC service. Env var: K8S_KMS_PLUGIN_SERVE_PORT.")

	// TLS parameters for the kubernetes facing TCP gRPC API (not unix socket)
	serveCmd.PersistentFlags().Bool("enable-tls", false, "Enable TLS on the TCP gRPC server. Not compatible when serving on unix socket. Env var: K8S_KMS_PLUGIN_SERVE_ENABLE_TLS")
	serveCmd.PersistentFlags().String("tls-ca", "certs/ca.crt", "TLS CA cert. Env var: K8S_KMS_PLUGIN_SERVE_TLS_CA.")
	serveCmd.PersistentFlags().String("tls-key", "certs/tls.key", "TLS server key. Env var: K8S_KMS_PLUGIN_SERVE_TLS_KEY")
	serveCmd.PersistentFlags().String("tls-certificate", "certs/tls.crt", "TLS server cert. Env var: K8S_KMS_PLUGIN_SERVE_TLS_CERTIFICATE")

	serveCmd.PersistentFlags().Bool("allow-any", false, "Allow any device (accepts all ids/secrets). Env var: K8S_KMS_PLUGIN_SERVE_ALLOW_ANY")

	// if the user chooses to run k8s-kms-plugin serve with unix socket, then do not configure TCP and TLS settings.
	serveCmd.MarkFlagsMutuallyExclusive("socket", "host")
	serveCmd.MarkFlagsMutuallyExclusive("socket", "port")
	serveCmd.MarkFlagsMutuallyExclusive("socket", "enable-tls")
	serveCmd.MarkFlagsMutuallyExclusive("socket", "tls-ca")
	serveCmd.MarkFlagsMutuallyExclusive("socket", "tls-key")
	serveCmd.MarkFlagsMutuallyExclusive("socket", "tls-certificate")

	// PKCS11 related options
	serveCmd.PersistentFlags().String("algorithm", "aes-gcm", "Set the algorithm for encryption/decryption. Possible values: aes-gcm, aes-cbc, rsa-oaep. Env var: K8S_KMS_PLUGIN_SERVE_ALGORITHM")
	serveCmd.RegisterFlagCompletionFunc("algorithm", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"aes-gcm", "aes-cbc", "rsa-oaep"}, cobra.ShellCompDirectiveNoFileComp
	})

	serveCmd.PersistentFlags().String("ca-id", defaultCaId, "Cert ID for CA Cert record. Env var: K8S_KMS_PLUGIN_SERVE_CA_ID")
	serveCmd.PersistentFlags().Bool("auto-create", false, "Auto create the keys if needed. Env var: K8S_KMS_PLUGIN_SERVE_AUTO_CREATE.")
	serveCmd.PersistentFlags().String("p11-key-label", "", "Key Label CKA_LABEL to use for encrypt/decrypt. Env var: K8S_KMS_PLUGIN_SERVE_P11_KEY_LABEL.")
	serveCmd.PersistentFlags().String("p11-hmac-label", "", "Key Label CKA_LABEL to use for sha based verifications. Env var: K8S_KMS_PLUGIN_SERVE_P11_HMAC_LABEL.")
	serveCmd.PersistentFlags().String("kek-id", "", "Key ID CKA_ID for KMS KEK. Env var: K8S_KMS_PLUGIN_SERVE_KEK_ID")
	serveCmd.PersistentFlags().String("hmac-id", "", "Key ID CKA_ID for KMS HMAC. Env var: K8S_KMS_PLUGIN_SERVE_HMAC_ID")
	serveCmd.PersistentFlags().StringP("native-path", "p", ".keys", "Path to key store for native provider(Files only). Env var: K8S_KMS_PLUGIN_SERVE_NATIVE_PATH.")
	serveCmd.PersistentFlags().String("p11-label", "", "P11 token label. Env var: K8S_KMS_PLUGIN_SERVE_P11_TOKEN")
	serveCmd.PersistentFlags().String("p11-lib", "", "Path to p11 library/client. Env var: K8S_KMS_PLUGIN_SERVE_P11_LIB")
	serveCmd.PersistentFlags().String("p11-pin", "", "P11 Pin. Env var: K8S_KMS_PLUGIN_SERVE_P11_PIN")
	serveCmd.PersistentFlags().Int("p11-slot", 0, "P11 token slot. Env var: K8S_KMS_PLUGIN_SERVE_P11_SLOT")
	// Provider
	serveCmd.PersistentFlags().String("provider", "p11", "Provider. Possible values: p11, softhsm, luna, dpod. Env var: K8S_KMS_PLUGIN_SERVE_PROVIDER.")
	serveCmd.RegisterFlagCompletionFunc("provider", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"p11", "softhsm", "luna", "dpod"}, cobra.ShellCompDirectiveNoFileComp
	})

	// At least one of KEK CKA_ID or CKA_LABEL must be provided by the user
	serveCmd.MarkFlagsOneRequired("kek-id", "p11-key-label")

	// To prevent mismatch between user provided CKA_ID and user provided CKA_LABEL, flags are Mutually Exclusive.
	// NewP11 make sure to retrieve the ID by label, or label by ID.
	serveCmd.MarkFlagsMutuallyExclusive("kek-id", "p11-key-label")
	serveCmd.MarkFlagsMutuallyExclusive("hmac-id", "p11-hmac-label")
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
	if vprFlgsServe.EnableTLS {
		switch vprFlgsServe.GrpcNetwork {
		case "tcp", "tcp4", "tcp6":
			// load TLS keys from PEM files.
			// TODO: add support for private key stored in a TPM ?
			tlsCreds, err := credentials.NewServerTLSFromFile(vprFlgsServe.ServerTLSCert, vprFlgsServe.ServerTLSKey)
			if err != nil {
				return fmt.Errorf("failed to load TLS keys: %w", err)
			}
			serverOptions = append(serverOptions, grpc.Creds(tlsCreds))
		case "unix":
			errOut := fmt.Errorf("grpcServe: unix gRPC listener does not support TLS")
			logrus.WithError(errOut).Error("wrong API serving settings")
			return errOut
		}
	}
	gs := grpc.NewServer(serverOptions...)

	k8skmsv2.RegisterKeyManagementServiceServer(gs, p)
	reflection.Register(gs)
	istio.RegisterKeyManagementServiceServer(gs, p)

	switch vprFlgsServe.GrpcNetwork {
	case "tcp", "tcp4", "tcp6":
		logrus.WithField("endpoint", gl.Addr().String()).
			Infof("serving k8s facing KMSv2 API on TCP: %s", gl.Addr().String())
		if vprFlgsServe.EnableTLS {
			logrus.Trace("TLS is enabled on gRPC server")
		}
	case "unix":
		logrus.WithField("endpoint", gl.Addr().String()).
			Infof("serving k8s facing KMSv2 API on unix socket: %s", gl.Addr().String())
	default:
		err = fmt.Errorf("unknown gRPC network listener type: %q", vprFlgsServe.GrpcNetwork)
		logrus.WithError(err).Error("unknown gRPC network listener type")
		return
	}

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
