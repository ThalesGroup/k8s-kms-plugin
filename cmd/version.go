package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/kms/v1"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the Version of the KMS",

	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, _, c, err := kms.GetClient(host, grpcPort)
		if err != nil {
			return err
		}
		var resp *kms.VersionResponse
		resp, err = c.Version(ctx, &kms.VersionRequest{})
		if err != nil {
			return err
		}

		fmt.Println(resp.Version)
		fmt.Println(resp.RuntimeName)
		fmt.Println(resp.RuntimeVersion)
		return err
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// versionCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// versionCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
