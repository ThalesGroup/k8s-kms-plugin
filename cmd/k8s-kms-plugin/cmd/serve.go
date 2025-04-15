/*
 * // Copyright 2025 Thales Group
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

// TODO replace github imports for :
//   - gose
//   - crypto11
import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
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

// cobra serve.go CLI Flags. They are mostly not used because we use viper that binds the cobra flags
// to the corresponding environment variables that viper reads.
var (
	algorithm     string
	allowAny      bool
	caTLSCert     string
	disableSocket bool
	enableTCP     bool
	serverTLSCert string
	serverTLSKey  string
)

type ViperFlagsServe struct {
	Algorithm     string `mapstructure:"algorithm"`
	AllowAny      bool   `mapstructure:"allow-any"`
	caTLSCert     string `mapstructure:"tls-ca"`
	disableSocket bool   `mapstructure:"disable-socket"`
	enableTCP     bool   `mapstructure:"enable-server"`
	serverTLSCert string `mapstructure:"tls-certificate"`
	serverTLSKey  string `mapstructure:"tls-key"`
}

// Initialize the ViperConfig struct with all the serve CLI flags bound to Viper env vars
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
	Short: "Serve KMS",
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

		if enableTCP {
			grpcAddr := fmt.Sprintf("%v:%d", host, grpcPort)

			if grpcTCP, err = net.Listen("tcp", grpcAddr); err != nil {
				return
			}

			g.Go(func() error { return grpcServe(grpcTCP, p) })
		}

		if !disableSocket {
			_ = os.Remove(socketPath)
			if grpcUNIX, err = net.Listen("unix", socketPath); err != nil {
				return
			}

			// Istiod runs with uid and gid 1337, but the plugin runs with uid 0 and
			// gid 1337.  Change the socket permissions so the group has read/write
			// access to the socket.
			os.Chmod(socketPath, 0775)
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

	// unix socket server options
	serveCmd.Flags().BoolVar(&disableSocket, "disable-socket", false, "Disable socket based server. Corresponding environment variable: K8S_KMS_PLUGIN_DISABLE_SOCKET.")

	// tcp server options
	serveCmd.Flags().BoolVar(&enableTCP, "enable-server", false, "Enable TLS based server. Corresponding environment variable: K8S_KMS_PLUGIN_ENABLE_SERVER.")
	serveCmd.Flags().StringVar(&caTLSCert, "tls-ca", "certs/ca.crt", "TLS CA cert. Corresponding environment variable: K8S_KMS_PLUGIN_TLS_CA.")
	serveCmd.Flags().StringVar(&serverTLSKey, "tls-key", "certs/tls.key", "TLS server key. Corresponding environment variable: K8S_KMS_PLUGIN_TLS_KEY")
	serveCmd.Flags().StringVar(&serverTLSCert, "tls-certificate", "certs/tls.crt", "TLS server cert. Corresponding environment variable: K8S_KMS_PLUGIN_TLS_CERTIFICATE")

	serveCmd.Flags().BoolVar(&allowAny, "allow-any", false, "Allow any device (accepts all ids/secrets). Corresponding environment variable: K8S_KMS_PLUGIN_ALLOW_ANY")

	serveCmd.Flags().StringVar(&algorithm, "algorithm", "aes-gcm", "Set the algorithm for encryption/decryption. Possible values: aes-gcm, aes-cbc, rsa-oaep. Corresponding environment variable: K8S_KMS_PLUGIN_ALGORITHM")
	serveCmd.RegisterFlagCompletionFunc("algorithm", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"aes-gcm", "aes-cbc", "rsa-oaep"}, cobra.ShellCompDirectiveNoFileComp
	})
}

func initProvider() (p providers.Provider, err error) {
	// init the algorithm to use in the kms from user input
	alg, err := algFromString(algorithm)
	if err != nil {
		return
	}

	// init the provider config from user input
	config := &crypto11.Config{}
	switch provider {
	case "p11", "softhsm":
		logrus.Debug("initProvider: case p11 or softhsm")
		config = &crypto11.Config{
			Path:            p11lib,
			Pin:             p11pin,
			UseGCMIVFromHSM: false,
		}

	case "luna", "dpod":
		logrus.Debug("initProvider: case luna HSM or dpod")
		config = &crypto11.Config{
			Path:            p11lib,
			Pin:             p11pin,
			UseGCMIVFromHSM: true,
			GCMIVFromHSMControl: crypto11.GCMIVFromHSMConfig{
				SupplyIvForHSMGCMEncrypt: false,
				SupplyIvForHSMGCMDecrypt: true,
			},
		}
	default:
		err = errors.New("unknown provider")
		return
	}

	if p11label != "" {
		config.TokenLabel = p11label
	} else {
		config.SlotNumber = &p11slot
	}
	// init the provider
	// TODO: See https://github.com/ThalesGroup/k8s-kms-plugin/issues/40#issuecomment-2593267852
	if p, err = providers.NewP11(config, createKey, dekKeyLabelName, hmacKeyName, alg); err != nil {
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
	logrus.Debugf("grpcServe: value of grpcPort user input: %d", grpcPort)

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
