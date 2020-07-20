package cmd

import (
	"errors"
	goflag "flag"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/go-openapi/loads"
	"github.com/golang/glog"
	"github.com/jessevdk/go-flags"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/operations"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/providers"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"net"
	"os"
	"path/filepath"
)

var (
	provider   string
	serverTLSCert   string
	serverTLSKey  string
	nativePath string
	keyId      string
	keyName    string
	p11lib     string
	p11slot    int
	p11label   string
	p11pin     string
	createKey  bool
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve KMS",

	RunE: func(cmd *cobra.Command, args []string) (err error) {
		goflag.Parse()

		g := new(errgroup.Group)
		grpcAddr := fmt.Sprintf("%v:%d", host, grpcPort)
		estAddr := fmt.Sprintf("%v:%d", host, estPort)
		var grpcTCP, estTCP, grpcUNIX  net.Listener
		if grpcTCP, err = net.Listen("tcp", grpcAddr); err != nil {
			return
		}
		if grpcTCP, err = net.Listen("tcp", estAddr); err != nil {
			return
		}
		_ = os.Remove(socketPath)
		if grpcUNIX, err = net.Listen("unix", socketPath); err != nil {
			return
		}

		g.Go(func() error { return estServe(estTCP) })
		g.Go(func() error { return grpcServe(grpcTCP) })
		g.Go(func() error { return grpcServe(grpcUNIX) })
		glog.Infof("KMS Plugin Listening on : %d", grpcPort)
		glog.Infof("EST Service Listening on : %d", estTCP)
		if err = g.Wait(); err != nil {
			glog.Exit(err)
		}

		return
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), ".sock"), "Unix Socket")
	serveCmd.Flags().StringVar(&serverTLSKey, "tls-key", "tls.key", "Key for Server TLS")
	serveCmd.Flags().StringVar(&serverTLSCert, "tls-certificate", "tls.crt", "Cert for Server TLS")
	// Here you will define your flags and configuration settings.

}

func estServe(gl net.Listener) (err error) {
	swaggerSpec, err := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
	if err != nil {
		glog.Fatalln(err)
	}
	api := operations.NewEstServerAPI(swaggerSpec)
	server := restapi.NewServer(api)
	defer server.Shutdown()

	parser := flags.NewParser(server, flags.Default)
	parser.ShortDescription = "est server"
	parser.LongDescription = "RFC 7030 (EST) server implementation"

	server.ConfigureFlags()
	for _, optsGroup := range api.CommandLineOptionsGroups {
		_, err := parser.AddGroup(optsGroup.ShortDescription, optsGroup.LongDescription, optsGroup.Options)
		if err != nil {
			glog.Fatalln(err)
		}
	}
	if _, err := parser.Parse(); err != nil {
		code := 1
		if fe, ok := err.(*flags.Error); ok {
			if fe.Type == flags.ErrHelp {
				code = 0
			}
		}
		os.Exit(code)
	}

	server.ConfigureAPI()

	return server.Serve()
}

func grpcServe(gl net.Listener) (err error) {
	var p providers.Provider

	switch provider {
	case "p11":
		config := &crypto11.Config{
			Path:       p11lib,
			TokenLabel: p11label,
			SlotNumber: &p11slot,
			Pin:        p11pin,

			UseGCMIVFromHSM: true,
		}
		if p, err = providers.NewP11(keyId, keyName, config, createKey); err != nil {
			return
		}
	case "native":
		config := &crypto11.Config{
			Path:       p11lib,
			TokenLabel: p11label,
			SlotNumber: &p11slot,
			Pin:        p11pin,

			UseGCMIVFromHSM: true,
		}
		if p, err = providers.NewP11(keyId, keyName, config, createKey); err != nil {
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
	}

	gs := grpc.NewServer(serverOptions...)
	reflection.Register(gs)
	istio.RegisterKeyManagementServiceServer(gs, p)
	return gs.Serve(gl)
}
