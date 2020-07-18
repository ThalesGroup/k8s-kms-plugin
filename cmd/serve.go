package cmd

import (
	"context"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/sirupsen/logrus"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/kms"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/providers"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
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
		logrus.SetLevel(logrus.DebugLevel)

		shutdown := make(chan error)
		var p providers.Provider

		if p, err = getProvider(); err != nil {
			return err
		}
		go serveSocket(p, shutdown)
		if !disableServer {
			go serveTCP(p, shutdown)
		}

		select {
		case e := <-shutdown:
			logrus.Error(e)
		}

		return
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), ".sock"), "Unix Socket")
	serveCmd.Flags().BoolVar(&disableServer, "disable-tcp", false, "Disable TCP Server ")
	serveCmd.Flags().StringVar(&host, "host", "0.0.0.0", "TCP Host")
	serveCmd.Flags().Int64Var(&port, "port", 31400, "TCP Port")
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

func getProvider() (p providers.Provider, err error) {
	switch strings.ToLower(provider) {
	case "native":
		p, err = providers.NewNative(nativePath)
	case "p11":
		config := &crypto11.Config{
			Path:        p11lib,
			TokenSerial: "",
			TokenLabel:  p11lib,
			SlotNumber:  &p11slot,
			Pin:         p11pin,
		}
		p, err = providers.NewP11(keyId, keyName, config, createKey)
	}
	return
}

func serveSocket(p providers.Provider, shutdown chan error) {

	_ = os.Remove(socketPath)
	k, err := kms.New(p, socketPath)
	if err != nil {
		shutdown <- err
		return
	}
	var lis net.Listener
	lis, err = net.Listen("unix", socketPath)
	if err != nil {
		shutdown <- err
		return
	}

	if err = k.Start(context.TODO(), shutdown, lis); err != nil {
		shutdown <- err
		return
	}
	return
}

func serveTCP(p providers.Provider, shutdown chan error) {
	k, err := kms.New(p, socketPath)
	if err != nil {
		shutdown <- err
		return
	}

	var lis net.Listener
	lis, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		shutdown <- err
		return
	}

	if err = k.Start(context.TODO(), shutdown, lis); err != nil {
		shutdown <- err
		return
	}
	return
}
