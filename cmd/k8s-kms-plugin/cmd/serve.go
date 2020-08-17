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
	"github.com/ThalesIgnite/crypto11"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/kms/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/keystore"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/providers"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	provider      string
	caTLSCert     string
	serverTLSCert string
	serverTLSKey  string
	kekKeyId      string
	estKeyId      string
	keyName       string
	p11lib        string
	p11slot       int
	p11label      string
	p11pin        string
	createKey     bool
	allowAny      bool
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve KMS",

	RunE: func(cmd *cobra.Command, args []string) (err error) {

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
		if a := os.Getenv("P11_PIN"); a != "" {
			p11pin = a
		}
		g := new(errgroup.Group)
		grpcAddr := fmt.Sprintf("%v:%d", host, grpcPort)
		var grpcTCP, grpcUNIX net.Listener
		if grpcTCP, err = net.Listen("tcp", grpcAddr); err != nil {
			return
		}

		if enableTCP {
			g.Go(func() error { return grpcServe(grpcTCP) })
			logrus.Infof("KMS Plugin Listening on : %d\n", grpcPort)
		}
		if !disableSocket {
			_ = os.Remove(socketPath)
			if grpcUNIX, err = net.Listen("unix", socketPath); err != nil {
				return
			}
			g.Go(func() error { return grpcServe(grpcUNIX) })
			logrus.Infof("KMS Plugin Listening at : %s\n", socketPath)

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
var keystoreKind, fileDir string
var ks keystore.KeyStore
var wrappedIntKek []byte

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run.sock"), "Unix Socket")

	//
	serveCmd.Flags().BoolVar(&enableTCP, "enable-server", false, "Enable TLS based server")
	serveCmd.Flags().BoolVar(&disableSocket, "disable-socket", false, "Disable socket based server")
	serveCmd.Flags().StringVar(&caTLSCert, "tls-ca", "certs/ca.crt", "TLS CA cert")
	serveCmd.Flags().StringVar(&serverTLSKey, "tls-key", "certs/tls.key", "TLS server key")
	serveCmd.Flags().StringVar(&serverTLSCert, "tls-certificate", "certs/tls.crt", "TLS server cert")
	// Here you will define your flags and configuration settings.
	serveCmd.Flags().StringVar(&estKeyId, "est-kid", "4f9f0b80-63af-4a83-b6c0-b2f06b93c272", "Key ID for EST Root CA SEK")
	serveCmd.Flags().StringVar(&kekKeyId, "kms-kid", "a37807cd-6d1a-4d75-813a-e120f30176f7", "Key ID for KMS KEK")
	serveCmd.Flags().StringVar(&p11lib, "p11-lib", "", "Path to p11 library/client")
	serveCmd.Flags().StringVar(&p11label, "p11-label", "", "P11 token label")
	serveCmd.Flags().IntVar(&p11slot, "p11-slot", 0, "P11 token slot")
	serveCmd.Flags().StringVar(&p11pin, "p11-pin", "", "P11 Pin")
	serveCmd.Flags().StringVar(&keyName, "p11-key-label", "k8s-kek", "Key Label to use for encrypt/decrypt")
	serveCmd.Flags().StringVarP(&nativePath, "native-path", "p", ".keys", "Path to key store for native provider(Files only)")
	serveCmd.Flags().BoolVar(&createKey, "auto-create", true, "Auto create the keys if needed")
	serveCmd.Flags().BoolVar(&allowAny, "allow-any", false, "Allow any device (accepts all ids/secrets)")

	// KeyStore
	serveCmd.Flags().StringVarP(&keystoreKind, "keystore", "k", "file", "Keystore Kind to store the JWK DEK Blobs")
	serveCmd.Flags().StringVar(&fileDir, "file-dir", "./.keystore", "Directory to use for the `file` based keystore")

}

func grpcServe(gl net.Listener) (err error) {
	var p providers.Provider
	// KeyStore startup
	switch strings.ToLower(keystoreKind) {
	case "file", "filesystem", "fs":

		if ks, err = keystore.NewFilePrivateKeyStore(fileDir); err != nil {
			return
		}
	default:
		ks = keystore.NewMemoryPrivateKeyStore(wrappedIntKek)
	}
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
		if p, err = providers.NewP11(config, ks, wrappedIntKek, createKey); err != nil {
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
		if p, err = providers.NewP11(config, ks, wrappedIntKek, createKey); err != nil {
			return
		}
	case "ekms":
		panic("unimplemented")
	default:
		err = errors.New("unknown provider")
		return
	}
	if err = p.LoadIntKek(); err != nil {
		return
	}
	// Create a gRPC server to host the services
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(p.UnaryInterceptor),
	}

	gs := grpc.NewServer(serverOptions...)
	reflection.Register(gs)
	kms.RegisterKeyManagementServiceServer(gs, p)
	logrus.Infof("Serving on socket: %v", socketPath)

START:
	if err = gs.Serve(gl); err != nil {
		logrus.Error(err)
		goto START
	}
	return
}
