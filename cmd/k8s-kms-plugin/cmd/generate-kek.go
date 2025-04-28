package cmd

import (
	"fmt"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	"github.com/spf13/cobra"
)

var (
	kekID string
)

var generateKEKCmd = &cobra.Command{
	Use:     "generate-kek",
	Short:   "Generate a KEK",
	GroupID: "kmscmdsgrpsupporting",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := generateKEK(); err != nil {
			return err
		}
		return nil
	},
}

func generateKEK() error {
	ctx, cancel, c, err := istio.GetClientSocket(socketPath, vprFlgsRoot.Timeout)
	defer cancel()
	if err != nil {
		return fmt.Errorf("could not open socket: %v", err)
	}

	genKEKResp, err := c.GenerateKEK(ctx, &istio.GenerateKEKRequest{
		KekKid: []byte(kekID),
	})
	if err != nil {
		return fmt.Errorf("generate KEK failed: %v", err)
	}
	fmt.Println("KEK ID:", string(genKEKResp.KekKid))

	return nil
}

func init() {
	rootCmd.AddCommand(generateKEKCmd)
	generateKEKCmd.Flags().StringVar(&kekID, "kek-id", "", "KEK ID to request")
}
