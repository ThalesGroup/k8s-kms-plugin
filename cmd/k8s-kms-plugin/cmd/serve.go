/*
 * // Copyright 2020 Thales DIS CPL Inc
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

import (
	"errors"
	"fmt"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	k8s "github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1beta1"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/ThalesIgnite/crypto11"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/providers"
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
	p11lib            string
	p11slot           int
	p11label          string
	p11pin            string
	createKey         bool
	allowAny          bool
)

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

		if a := os.Getenv("P11_PIN_FILE"); a != "" {
			var p11pinBytes []byte
			p11pinBytes, err = ioutil.ReadFile(a)
			if err != nil {
				logrus.Error(err)
				return
			}
			p11pin = strings.TrimSpace(string(p11pinBytes))

			logrus.Infof("Loaded P11 PIN from file: %v", a)
		} else if a := os.Getenv("P11_PIN"); a != "" {
			p11pin = a
			logrus.Info("Loaded P11 PIN from ENV variable. Never use this in production!")
		}
		g := new(errgroup.Group)
		grpcAddr := fmt.Sprintf("%v:%d", host, grpcPort)
		var grpcTCP, grpcUNIX net.Listener
		if grpcTCP, err = net.Listen("tcp", grpcAddr); err != nil {
			return
		}

		if enableTCP {
			g.Go(func() error { return grpcServe(grpcTCP) })
			logrus.Infof("KMS Plugin Listening on : %v\n", grpcPort)
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
			g.Go(func() error { return grpcServe(grpcUNIX) })
			logrus.Infof("KMS Plugin Listening on : %v\n", socketPath)

		}

		if err = g.Wait(); err != nil {
			logrus.Error(err)
			panic(err)
		}

		return
	},
}
var enableTCP, disableSocket bool
var nativePath string

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket")

	//
	serveCmd.Flags().BoolVar(&enableTCP, "enable-server", false, "Enable TLS based server")
	serveCmd.Flags().BoolVar(&disableSocket, "disable-socket", false, "Disable socket based server")
	serveCmd.Flags().StringVar(&caTLSCert, "tls-ca", "certs/ca.crt", "TLS CA cert")
	serveCmd.Flags().StringVar(&serverTLSKey, "tls-key", "certs/tls.key", "TLS server key")
	serveCmd.Flags().StringVar(&serverTLSCert, "tls-certificate", "certs/tls.crt", "TLS server cert")
	// Here you will define your flags and configuration settings.

	serveCmd.Flags().BoolVar(&allowAny, "allow-any", false, "Allow any device (accepts all ids/secrets)")

}

func grpcServe(gl net.Listener) (err error) {
	var p providers.Provider

	switch provider {
	case "p11", "softhsm":
		config := &crypto11.Config{
			Path:            p11lib,
			Pin:             p11pin,
			UseGCMIVFromHSM: true,
		}
		if p11label != "" {
			config.TokenLabel = p11label
		} else {
			config.SlotNumber = &p11slot
		}
		if p, err = providers.NewP11(config, createKey, defaultDekKeyName); err != nil {
			return
		}
	case "luna", "dpod":
		config := &crypto11.Config{
			Path:            p11lib,
			Pin:             p11pin,
			UseGCMIVFromHSM: true,
		}
		if p11label != "" {
			config.TokenLabel = p11label
		} else {
			config.SlotNumber = &p11slot
		}
		if p, err = providers.NewP11(config, createKey, defaultDekKeyName); err != nil {
			return
		}
	case "ekms":
		panic("unimplemented")
	default:
		err = errors.New("unknown provider")
		return
	}
	// Create a gRPC server to host the services
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(p.UnaryInterceptor),
		grpc.UnknownServiceHandler(unknownServiceHandler),
	}

	gs := grpc.NewServer(serverOptions...)
	k8s.RegisterKeyManagementServiceServer(gs, p)
	reflection.Register(gs)
	istio.RegisterKeyManagementServiceServer(gs, p)
	logrus.Infof("Serving on socket: %s", socketPath)

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
