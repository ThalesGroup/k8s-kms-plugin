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
	"strconv"
)

var (
	provider      string
	caTLSCert     string
	serverTLSCert string
	serverTLSKey  string
	nativePath    string
	estKeyId      string
	kekKeyId      string
	keyName       string
	p11lib        string
	p11slot       int
	p11label      string
	p11pin        string
	createKey     bool
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve KMS",

	RunE: func(cmd *cobra.Command, args []string) (err error) {
		goflag.Parse()
		var swaggerSpec *loads.Document
		swaggerSpec, err = loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
		if err != nil {
			glog.Fatalln(err)
		}
		estServer = restapi.NewServer(api)
		estServer.TLSCACertificate = caTLSCert
		estServer.TLSCertificateKey = serverTLSKey
		estServer.TLSCertificate = serverTLSCert
		if err = estServer.AddConfig(caTLSCert, serverTLSKey, serverTLSCert); err != nil {
			return
		}
		api = operations.NewEstServerAPI(swaggerSpec)
		if a := os.Getenv("P11_LIB"); a != "" {
			p11lib = a
		}
		if a := os.Getenv("P11_LABEL"); a != "" {
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
		_ = os.Remove(socketPath)
		if grpcUNIX, err = net.Listen("unix", socketPath); err != nil {
			return
		}

		g.Go(func() error { return estServe() })
		g.Go(func() error { return grpcServe(grpcTCP) })
		g.Go(func() error { return grpcServe(grpcUNIX) })
		fmt.Printf("KMS Plugin Listening on : %d\n", grpcPort)
		fmt.Printf("EST Service Listening on : %d\n", estPort)
		if err = g.Wait(); err != nil {
			glog.Exit(err)
		}

		return
	},
}
var estServer *restapi.Server
var api *operations.EstServerAPI

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), ".sock"), "Unix Socket")
	serveCmd.Flags().StringVar(&caTLSCert, "tls-ca", "certs/ca.crt", "EST TLS")
	serveCmd.Flags().StringVar(&serverTLSKey, "tls-key", "certs/tls.key", "Key for Server TLS")
	serveCmd.Flags().StringVar(&serverTLSCert, "tls-certificate", "certs/tls.crt", "Cert for Server TLS")
	// Here you will define your flags and configuration settings.
	serveCmd.Flags().StringVar(&kekKeyId, "est-key-id", "4f9f0b80-63af-4a83-b6c0-b2f06b93c272", "Key ID for EST CA")
	serveCmd.Flags().StringVar(&kekKeyId, "kek-key-id", "a37807cd-6d1a-4d75-813a-e120f30176f7", "Key ID for KEK")
	serveCmd.Flags().StringVar(&p11lib, "p11-lib", "", "Path to p11 library/client")
	serveCmd.Flags().StringVar(&p11label, "p11-label", "", "P11 token label")
	serveCmd.Flags().IntVar(&p11slot, "p11-slot", 0, "P11 token slot")
	serveCmd.Flags().StringVar(&p11pin, "p11-pin", "", "P11 Pin")
	serveCmd.Flags().StringVar(&keyName, "p11-key-label", "k8s-kek", "Key Label to use for encrypt/decrypt")
	serveCmd.Flags().BoolVar(&createKey, "auto-create", true, "Auto create the keys if neededsd")
	swaggerSpec, err := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
	if err != nil {
		glog.Fatalln(err)
	}
	api = operations.NewEstServerAPI(swaggerSpec)

}

func estServe() (err error) {

	defer estServer.Shutdown()

	parser := flags.NewParser(estServer, flags.Default)
	parser.ShortDescription = "est server"
	parser.LongDescription = "RFC 7030 (EST) server implementation"

	estServer.ConfigureFlags()
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
	estServer.Port = int(estPort)
	estServer.ConfigureAPI()

	return estServer.Serve()
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
		if p, err = providers.NewP11(kekKeyId, keyName, config, createKey); err != nil {
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
		if p, err = providers.NewP11(kekKeyId, keyName, config, createKey); err != nil {
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
