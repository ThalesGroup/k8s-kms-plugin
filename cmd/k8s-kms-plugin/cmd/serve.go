// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

// TODO replace github imports for :
//   - gose
//   - crypto11
import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose/jose"

	"github.com/ThalesGroup/k8s-kms-plugin/pkg/logging"
	"github.com/ThalesGroup/k8s-kms-plugin/pkg/providers"
	version "github.com/ThalesGroup/k8s-kms-plugin/pkg/version"
	k8skmsv2 "k8s.io/kms/apis/v2"

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
	AlgorithmFamily string `mapstructure:"algorithm-family"`
	NativePath      string `mapstructure:"native-path"`
	P11Label        string `mapstructure:"p11-label"`
	P11Lib          string `mapstructure:"p11-lib"`
	P11Pin          string `mapstructure:"p11-pin"`
	P11Slot         int    `mapstructure:"p11-slot"`
	Provider        string `mapstructure:"provider"`
	SocketPath      string `mapstructure:"socket"` // Unix socket path for TPM or HSM

	// PKCS #11 CKA_ID and CKA_LABEL of active KEK key
	CreateKey    bool   `mapstructure:"auto-create"`
	DekKeyLabel  string `mapstructure:"p11-key-label"`  // active DEK key CKA_LABEL
	HmacKeyID    string `mapstructure:"p11-hmac-id"`    // active HMAC key CKA_ID
	HmacKeyLabel string `mapstructure:"p11-hmac-label"` // active HMAC key CKA_LABEL
	KekKeyID     string `mapstructure:"p11-key-id"`     // active KEK key CKA_ID
}

// Declare the viper CLI flag values buffer
var vprFlgsServe ViperFlagsServe

// AlgorithmFamily is the user-facing algorithm selector. It names the cryptographic
// mechanism only — key size and parameter set are derived from the HSM key at runtime.
type AlgorithmFamily string

const (
	AlgorithmFamilyAESGCM  AlgorithmFamily = "aes-gcm"
	AlgorithmFamilyAESCBC  AlgorithmFamily = "aes-cbc"
	AlgorithmFamilyRSAOAEP AlgorithmFamily = "rsa-oaep"
	AlgorithmFamilyMLKEM   AlgorithmFamily = "ml-kem"
)

// AlgorithmFamily implements pflag.Value so cobra validates the flag at parse time.
func (a *AlgorithmFamily) String() string { return string(*a) }
func (a *AlgorithmFamily) Type() string   { return "algorithmFamily" }
func (a *AlgorithmFamily) Set(s string) error {
	if err := validateAlgorithmFamily(s); err != nil {
		return err
	}
	*a = AlgorithmFamily(s)
	return nil
}

// validateAlgorithmFamily is used both by AlgorithmFamily.Set (CLI flag path) and
// PersistentPreRunE (config file / env var path).
func validateAlgorithmFamily(s string) error {
	switch AlgorithmFamily(s) {
	case AlgorithmFamilyAESGCM, AlgorithmFamilyAESCBC, AlgorithmFamilyRSAOAEP, AlgorithmFamilyMLKEM:
		return nil
	default:
		return fmt.Errorf("must be one of aes-gcm, aes-cbc, rsa-oaep, ml-kem; got %q", s)
	}
}

const (
	// maxCkaLabelBytes is the PKCS#11 CKA_LABEL maximum (mirrored from pkg/providers).
	maxCkaLabelBytes = 255
	// maxUnixSocketPathLen is the Linux UNIX_PATH_MAX minus one byte for the null terminator.
	maxUnixSocketPathLen = 107
)

// sanitizeViperFlagsServe validates all user-controlled fields in ViperFlagsServe after
// viper has resolved them from all input sources (CLI flags, config file, env vars).
func sanitizeViperFlagsServe(f *ViperFlagsServe) error {
	if err := validateAlgorithmFamily(f.AlgorithmFamily); err != nil {
		return fmt.Errorf("--algorithm-family: %w", err)
	}
	if len(f.P11Label) > maxCkaLabelBytes {
		return fmt.Errorf("--p11-label: length %d exceeds maximum of %d bytes", len(f.P11Label), maxCkaLabelBytes)
	}
	if len(f.DekKeyLabel) > maxCkaLabelBytes {
		return fmt.Errorf("--p11-key-label: length %d exceeds maximum of %d bytes", len(f.DekKeyLabel), maxCkaLabelBytes)
	}
	if len(f.HmacKeyLabel) > maxCkaLabelBytes {
		return fmt.Errorf("--p11-hmac-label: length %d exceeds maximum of %d bytes", len(f.HmacKeyLabel), maxCkaLabelBytes)
	}
	if !f.DisableSocket && len(f.SocketPath) > maxUnixSocketPathLen {
		return fmt.Errorf("--socket: path length %d exceeds Unix socket maximum of %d bytes", len(f.SocketPath), maxUnixSocketPathLen)
	}
	return nil
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
		--algorithm-family rsa-oaep

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
		--algorithm-family aes-cbc
`,
	GroupID: "kmscmdsgrpmain",
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsServe); err != nil {
			slog.Error("Error initializing Viper", "cobra_cmd", cmd.Use, "error", err)
			return err
		}
		if err := sanitizeViperFlagsServe(&vprFlgsServe); err != nil {
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// Show the version of the k8s-kms-plugin and commit ID
		version.LogVersion()

		if vprFlgsServe.P11Pin, err = resolvePin(viper.GetViper(), "p11-pin", "Enter HSM PIN: "); err != nil {
			return
		}

		// Don't panic/exit if we have a PKCS#11 error.
		// Sleep forever instead.
		var p providers.Provider
		p, err = initProvider()
		if err != nil && providers.IsPKCS11AuthenticationError(err) {
			slog.Error("PKCS11 authentication error detected. Further retries may cause the token to be erased.", "cobra_cmd", cmd.Use, "error", err)
			slog.Warn("Process will now sleep indefinitely to prevent further damage...", "cobra_cmd", cmd.Use)
			time.Sleep(8760 * time.Hour)
		}

		if err != nil {
			logging.Fatal("failed to initialize provider", "cobra_cmd", cmd.Use, "error", err)
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

			// Grant group read/write so a co-located client (e.g. kube-apiserver
			// running under a shared gid) can connect to the socket.
			os.Chmod(vprFlgsServe.SocketPath, 0775)
			g.Go(func() error { return grpcServe(grpcUNIX, p) })
		}

		if err = g.Wait(); err != nil {
			slog.Error("gRPC server error", "cobra_cmd", cmd.Use, "error", err)
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

	algFamilyDefault := AlgorithmFamilyAESGCM
	serveCmd.PersistentFlags().Var(&algFamilyDefault, "algorithm-family", "Encryption mechanism. Possible values: aes-gcm, aes-cbc, rsa-oaep, ml-kem.")
	serveCmd.RegisterFlagCompletionFunc("algorithm-family", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"}, cobra.ShellCompDirectiveNoFileComp
	})

	// These flags comes from root
	// These flags does not need to store their values in variable because we use the viper structure ViperFlagsServe to do this
	serveCmd.PersistentFlags().Bool("auto-create", false, "Auto create the keys if needed.")
	serveCmd.PersistentFlags().String("p11-key-label", "", "Key Label (CKA_LABEL) for the KMS KEK. The key must have a CKA_ID set on the HSM — it is stored as the KEK ID in Kubernetes etcd.")
	serveCmd.PersistentFlags().String("p11-hmac-label", "", "Key Label (CKA_LABEL) for the HMAC key. The key must have a CKA_ID set on the HSM.")
	serveCmd.PersistentFlags().String("host", "0.0.0.0", "Hostname without port.")
	serveCmd.PersistentFlags().String("p11-key-id", "", "Key ID CKA_ID for KMS KEK.")
	serveCmd.PersistentFlags().String("p11-hmac-id", "", "Key ID CKA_ID for KMS HMAC.")
	serveCmd.PersistentFlags().StringP("native-path", "p", ".keys", "Path to key store for native provider(Files only).")
	serveCmd.PersistentFlags().String("p11-label", "", "P11 token label.")
	serveCmd.PersistentFlags().String("p11-lib", "", "Path to p11 library/client.")
	serveCmd.PersistentFlags().String("p11-pin", "", "HSM PIN. If omitted, prompted interactively (input hidden). Pass an empty string explicitly to use a no-PIN token.")
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
	// Validated by sanitizeViperFlagsServe; cast directly to the provider sentinel.
	alg := jose.Alg(vprFlgsServe.AlgorithmFamily)

	// init the provider config from user input
	config := &crypto11.Config{}
	switch vprFlgsServe.Provider {
	case "p11", "softhsm":
		slog.Log(context.Background(), logging.LevelTrace, "initProvider: case p11 or softhsm")
		config = &crypto11.Config{
			Path:            vprFlgsServe.P11Lib,
			Pin:             vprFlgsServe.P11Pin,
			UseGCMIVFromHSM: false,
		}

	case "luna", "dpod":
		slog.Log(context.Background(), logging.LevelTrace, "initProvider: case luna HSM or dpod")
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
		slog.Error("unknown provider", "provider", vprFlgsServe.Provider)
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
	slog.Log(context.Background(), logging.LevelTrace, "grpcServe")

	// Create a gRPC server to host the services
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(p.UnaryInterceptor),
		grpc.UnknownServiceHandler(unknownServiceHandler),
	}
	gs := grpc.NewServer(serverOptions...)

	k8skmsv2.RegisterKeyManagementServiceServer(gs, p)
	reflection.Register(gs)

	slog.Info("serving on socket", "address", gl.Addr().String())
	slog.Log(context.Background(), logging.LevelTrace, "grpc port", "port", vprFlgsServe.Port)

START:
	if err = gs.Serve(gl); err != nil {
		slog.Error("gRPC serve error", "error", err)
		goto START
	}
	return
}

func unknownServiceHandler(srv interface{}, stream grpc.ServerStream) error {
	typeOfSrv := reflect.TypeOf(srv)
	slog.Info("unknown service handler", "type", typeOfSrv, "service", srv)
	return nil
}
