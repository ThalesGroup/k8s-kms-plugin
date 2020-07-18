package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the Version of the KMS",

	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, _, c := getClient()
		var resp *v1beta1.VersionResponse
		resp, err = c.Version(ctx, &v1beta1.VersionRequest{})
		if err != nil {
			return
		}

		fmt.Println(resp.Version)
		fmt.Println(resp.RuntimeName)
		fmt.Println(resp.RuntimeVersion)
		return
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
