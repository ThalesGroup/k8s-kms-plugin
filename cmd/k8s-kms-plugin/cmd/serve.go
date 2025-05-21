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
	k8s "github.com/ThalesGroup/k8s-kms-plugin/apis/k8s/v1beta1"
	version "github.com/ThalesGroup/k8s-kms-plugin/pkg/version"

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
	Algorithm     string `mapstructure:"algorithm"`
	AllowAny      bool   `mapstructure:"allow-any"`
	CaTLSCert     string `mapstructure:"tls-ca"`
	DisableSocket bool   `mapstructure:"disable-socket"`
	EnableTCP     bool   `mapstructure:"enable-server"`
	ServerTLSCert string `mapstructure:"tls-certificate"`
	ServerTLSKey  string `mapstructure:"tls-key"`

	// These flags have been moved from root to serve
	CaID         string `mapstructure:"ca-id"`
	CreateKey    bool   `mapstructure:"auto-create"`
	DekKeyLabel  string `mapstructure:"p11-key-label"`
	HmacKeyLabel string `mapstructure:"p11-hmac-label"`
	Host         string `mapstructure:"host"`
	KekKeyID     string `mapstructure:"kek-id"`
	NativePath   string `mapstructure:"native-path"`
	P11Label     string `mapstructure:"p11-label"`
	P11Lib       string `mapstructure:"p11-lib"`
	P11Pin       string `mapstructure:"p11-pin"`
	P11Slot      int    `mapstructure:"p11-slot"`
	Port         uint16 `mapstructure:"port"`
	Provider     string `mapstructure:"provider"`

	SocketPath string `mapstructure:"socket"`
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
	Use:     "serve",
	Short:   "Serve KMS",
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
	serveCmd.Flags().Bool("disable-socket", false, "Disable socket based server. Env var: K8S_KMS_PLUGIN_SERVE_DISABLE_SOCKET.")

	// tcp server options
	serveCmd.Flags().Bool("enable-server", false, "Enable TLS based server. Env var: K8S_KMS_PLUGIN_SERVE_ENABLE_SERVER.")
	serveCmd.Flags().String("tls-ca", "certs/ca.crt", "TLS CA cert. Env var: K8S_KMS_PLUGIN_SERVE_TLS_CA.")
	serveCmd.Flags().String("tls-key", "certs/tls.key", "TLS server key. Env var: K8S_KMS_PLUGIN_SERVE_TLS_KEY")
	serveCmd.Flags().String("tls-certificate", "certs/tls.crt", "TLS server cert. Env var: K8S_KMS_PLUGIN_SERVE_TLS_CERTIFICATE")

	serveCmd.Flags().Bool("allow-any", false, "Allow any device (accepts all ids/secrets). Env var: K8S_KMS_PLUGIN_SERVE_ALLOW_ANY")

	serveCmd.Flags().String("algorithm", "aes-gcm", "Set the algorithm for encryption/decryption. Possible values: aes-gcm, aes-cbc, rsa-oaep. Env var: K8S_KMS_PLUGIN_SERVE_ALGORITHM")
	serveCmd.RegisterFlagCompletionFunc("algorithm", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"aes-gcm", "aes-cbc", "rsa-oaep"}, cobra.ShellCompDirectiveNoFileComp
	})

	// These flags comes from root
	// These flags does not need to store their values in variable because we use the viper structure ViperFlagsServe to do this
	serveCmd.Flags().String("ca-id", defaultCaId, "Cert ID for CA Cert record. Env var: K8S_KMS_PLUGIN_SERVE_CA_ID")
	serveCmd.Flags().Bool("auto-create", false, "Auto create the keys if needed. Env var: K8S_KMS_PLUGIN_SERVE_AUTO_CREATE.")
	serveCmd.Flags().String("p11-key-label", "k8s-dek", "Key Label to use for encrypt/decrypt. Env var: K8S_KMS_PLUGIN_SERVE_P11_KEY_LABEL.")
	serveCmd.Flags().String("p11-hmac-label", "k8s-hmac", "Key Label to use for sha based verifications. Env var: K8S_KMS_PLUGIN_SERVE_P11_HMAC_LABEL.")
	serveCmd.Flags().String("host", "0.0.0.0", "Hostname without port. Env var: K8S_KMS_PLUGIN_SERVE_HOST.")
	serveCmd.Flags().String("kek-id", defaultKekId, "Key ID for KMS KEK. Env var: K8S_KMS_PLUGIN_SERVE_KEK_ID")
	serveCmd.Flags().StringP("native-path", "p", ".keys", "Path to key store for native provider(Files only). Env var: K8S_KMS_PLUGIN_SERVE_NATIVE_PATH.")
	serveCmd.Flags().String("p11-label", "", "P11 token label. Env var: K8S_KMS_PLUGIN_SERVE_P11_TOKEN")
	serveCmd.Flags().String("p11-lib", "", "Path to p11 library/client. Env var: K8S_KMS_PLUGIN_SERVE_P11_LIB")
	serveCmd.Flags().String("p11-pin", "", "P11 Pin. Env var: K8S_KMS_PLUGIN_SERVE_P11_PIN")
	serveCmd.Flags().Int("p11-slot", 0, "P11 token slot. Env var: K8S_KMS_PLUGIN_SERVE_P11_SLOT")
	serveCmd.Flags().Uint16("port", 31400, "TCP Port for gRPC service. Env var: K8S_KMS_PLUGIN_SERVE_PORT.")
	// Provider
	serveCmd.Flags().String("provider", "p11", "Provider. Possible values: p11, softhsm, luna, dpod. Env var: K8S_KMS_PLUGIN_SERVE_PROVIDER.")
	serveCmd.RegisterFlagCompletionFunc("provider", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"p11", "softhsm", "luna", "dpod"}, cobra.ShellCompDirectiveNoFileComp
	})

	// Socket
	serveCmd.Flags().String("socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_SERVE_KEK_SOCKET")
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
	// init the provider
	// TODO: See https://github.com/ThalesGroup/k8s-kms-plugin/issues/40#issuecomment-2593267852
	if p, err = providers.NewP11(config, vprFlgsServe.CreateKey, vprFlgsServe.DekKeyLabel, vprFlgsServe.HmacKeyLabel, alg); err != nil {
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

	k8s.RegisterKeyManagementServiceServer(gs, p)
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
