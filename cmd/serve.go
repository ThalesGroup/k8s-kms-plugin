package cmd

import (
	"errors"
	goflag "flag"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/golang/glog"
	"github.com/soheilhy/cmux"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
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

		cmux.New()
		g := new(errgroup.Group)
		addr := fmt.Sprintf("%v:%d", host, port)
		var network, socket net.Listener
		if network, err = net.Listen("tcp", addr); err != nil {
			return
		}
		_ = os.Remove(socketPath)
		if socket, err = net.Listen("unix", socketPath); err != nil {
			return
		}

		g.Go(func() error { return grpcServe(network) })
		g.Go(func() error { return grpcServe(socket) })
		glog.Infof("Listening on : %d", port)
		if err = g.Wait(); err != nil {
			glog.Exit(err)
		}

		return
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), ".sock"), "Unix Socket")

	// Here you will define your flags and configuration settings.
	serveCmd.Flags().StringVar(&provider, "provider", "p11", "Provider to use for backend")

	serveCmd.Flags().StringVar(&nativePath, "native-path", filepath.Join(os.TempDir(), "native_keys"), "Path to store native keys")

	// P11 specific
	serveCmd.Flags().StringVar(&p11lib, "p11-lib", "", "Path to p11 library/client")
	serveCmd.Flags().StringVar(&p11label, "p11-label", "", "P11 token label")
	serveCmd.Flags().IntVar(&p11slot, "p11-slot", 0, "P11 token slot")
	serveCmd.Flags().StringVar(&p11pin, "p11-pin", "", "P11 Pin")
	serveCmd.Flags().StringVar(&keyName, "p11-key-label", "k8s-kek", "Key Label to use for encrypt/decrypt")
	serveCmd.Flags().BoolVar(&createKey, "auto-create", false, "Auto create the key")
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
