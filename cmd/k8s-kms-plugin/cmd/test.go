/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"golang.org/x/sync/errgroup"
	"os"
	"path/filepath"
	"time"
)

var loop bool
var loopTime int

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test connectivety to the socket for some encrypt/decrypt",

	Run: func(cmd *cobra.Command, args []string) {
		// Istio Tests against the socket

		g := &errgroup.Group{}
		if loop {
			g.Go(loopTestRun)
		} else {
			g.Go(runTest)
		}
		g.Wait()
	},
}

func loopTestRun() error {
	for {
		runTest()
		time.Sleep(time.Duration(loopTime) * time.Second)
	}
	return nil
}
func shutdownsafely() (err error) {
	logrus.Infof("While the test is complete, we'll just keep the process alive so the pod doesn't die... ")
	// TODO	"this can become a Job later on, maybe if there is a way to share the socket? So the job can close successfully vs restart again.

	for {
		// Sleep forever
		time.Sleep((time.Duration(loopTime)) * time.Second)
	}
	return
}
func runTest() error {
	ctx, cancel, c, err := istio.GetClientSocket(socketPath)
	defer cancel()
	if err != nil {
		logrus.Fatal(err)
		return err
	}

	logrus.Info("Test 1 - GenerateDEK ")
	var genDEKResp *istio.GenerateDEKResponse
	if genDEKResp, err = c.GenerateDEK(ctx, &istio.GenerateDEKRequest{
		Size: 32,
		Kind: istio.KeyKind_AES,
	}); err != nil {
		logrus.Fatal(err)

		return err
	}

	logrus.Infof("Returned WrappedDEK: %s", genDEKResp.EncryptedKeyBlob)

	logrus.Info("Test 2 - GenerateSEK RSA")
	var resp *istio.GenerateSEKResponse
	if resp, err = c.GenerateSEK(ctx, &istio.GenerateSEKRequest{
		Size: 4096,
		Kind: istio.KeyKind_RSA,
	}); err != nil {
		logrus.Fatal(err)
		return err
	}

	logrus.Infof("Returned WrappedSEK: %s", resp.EncryptedSekBlob)
	return shutdownsafely()

}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(os.TempDir(), ".sock"), "Unix Socket")
	testCmd.Flags().BoolVar(&loop, "loop", false, "Should we run the test in a loop?")
	testCmd.Flags().IntVar(&loopTime, "loop-sleep", 10, "How many seconds to sleep between test runs ")
	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// testCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// testCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
