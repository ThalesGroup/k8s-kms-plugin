package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
)

var (
	kekID string
)

var generateKEKCmd = &cobra.Command{
	Use:   "generate-kek",
	Short: "Generate a KEK",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := generateKEK(); err != nil {
			return err
		}
		return nil
	},
}

func generateKEK() error {
	ctx, cancel, c, err := istio.GetClientSocket(socketPath, timeout)
	defer cancel()
	if err != nil {
		return fmt.Errorf("Could not open socket: %v", err)
	}

	genKEKResp, err := c.GenerateKEK(ctx, &istio.GenerateKEKRequest{
		KekKid: []byte(kekID),
	})
	if err != nil {
		return fmt.Errorf("Generate KEK failed: %v", err)
	}
	fmt.Println("KEK ID:", string(genKEKResp.KekKid))

	return nil
}

func init() {
	rootCmd.AddCommand(generateKEKCmd)
	generateKEKCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), "run", "hsm-plugin-server.sock"), "Unix Socket")
	generateKEKCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Timeout Duration")
	generateKEKCmd.Flags().StringVar(&kekID, "kek-id", "", "KEK ID to request")
}
