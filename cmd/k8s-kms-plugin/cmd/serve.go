/*
 * // Copyright 2024 Thales Group 2020 Thales DIS CPL Inc
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
	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/jose"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	k8s "github.com/ThalesGroup/k8s-kms-plugin/apis/k8s/v1beta1"

	"github.com/ThalesGroup/k8s-kms-plugin/pkg/providers"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	provider          string
	caTLSCert         string
	serverTLSCert     string
	serverTLSKey      string
	kekKeyId          string
	caId              string
	defaultDekKeyName string
	hmacKeyName       string
	p11lib            string
	p11slot           int
	p11label          string
	p11pin            string
	createKey         bool
	allowAny          bool
	nativePath        string
	enableTCP         bool
	disableSocket     bool
	algorithm         string
)

// Algorithm supports user input for configuration
type Algorithm struct {
	slug string
}

var (
	UNKNOWNALG = Algorithm{""}
	AESGCM     = Algorithm{"aes-gcm"}
	AESCBC     = Algorithm{"aes-cbc"}
)

func algFromString(s string) (jose.Alg, error) {
	switch s {
	case AESGCM.slug:
		return jose.AlgA256GCM, nil
	case AESCBC.slug:
		return jose.AlgA256CBC, nil
	default:
		return "", gose.ErrInvalidAlgorithm
	}
}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve KMS",

	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if a := os.Getenv("SOCKET"); a != "" {
			socketPath = a
		}
		if a := os.Getenv("P11_LIB"); a != "" {
			p11lib = a
		}
		if a := os.Getenv("P11_TOKEN"); a != "" {
			p11label = a
		}

		if a := os.Getenv("P11_SLOT"); a != "" {
			if p11slot, err = strconv.Atoi(a); err != nil {
				return
			}
		}

		// Don't panic/exit if we have a PKCS#11 error.
		// Sleep forever instead.
		var p providers.Provider
		if a := os.Getenv("P11_PIN_FILE"); a != "" {
			var p11pinBytes []byte
			p11pinBytes, err = ioutil.ReadFile(a)
			if err != nil {
				logrus.Error(err)
				return err
			}
			p11pin = strings.TrimSpace(string(p11pinBytes))
			logrus.Infof("Loaded P11 PIN from file: %v", a)
		}

		p, err = initProvider()
		if err != nil && providers.IsPKCS11AuthenticationError(err) {
			logrus.Errorf("got pkcs11 error: %v, further retries may cause the token to be erased.")
			logrus.Errorf("sleeping forever.....")
			time.Sleep(8760 * time.Hour)
		}

		if err != nil {
			logrus.Fatalf("failed to initialize provider: %v", err)
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
			logrus.Error(err)
		}

		return
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// unix socket server options
	serveCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket")
	serveCmd.Flags().BoolVar(&disableSocket, "disable-socket", false, "Disable socket based server")

	// tcp server options
	serveCmd.Flags().BoolVar(&enableTCP, "enable-server", false, "Enable TLS based server")
	serveCmd.Flags().StringVar(&caTLSCert, "tls-ca", "certs/ca.crt", "TLS CA cert")
	serveCmd.Flags().StringVar(&serverTLSKey, "tls-key", "certs/tls.key", "TLS server key")
	serveCmd.Flags().StringVar(&serverTLSCert, "tls-certificate", "certs/tls.crt", "TLS server cert")

	serveCmd.Flags().BoolVar(&allowAny, "allow-any", false, "Allow any device (accepts all ids/secrets)")

	serveCmd.Flags().StringVar(&algorithm, "algorithm", "aes-gcm", "Set the algorithm for encryption/decryption (accepts: aes-gcm, aes-cbc)")
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
		config = &crypto11.Config{
			Path:            p11lib,
			Pin:             p11pin,
			UseGCMIVFromHSM: false,
		}

	case "luna", "dpod":
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
	if p, err = providers.NewP11(config, createKey, defaultDekKeyName, hmacKeyName, alg); err != nil {
		return
	}
	return
}

func grpcServe(gl net.Listener, p providers.Provider) (err error) {

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
