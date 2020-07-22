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
	"flag"
	"github.com/go-openapi/runtime"
	client2 "github.com/go-openapi/runtime/client"
	"time"

	//"crypto/x509/pkix"
	"fmt"
	"github.com/go-openapi/strfmt"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/client"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/client/operation"
)

var trustUnknownCA, retry bool

// enrollCmd represents the init command
var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll to a k8s-kms-plugin endpoint",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("enrolling")
		flag.Parse()

		tc, err := client2.TLSClient(client2.TLSClientOptions{
			InsecureSkipVerify: trustUnknownCA,
		})
		ts := client2.NewWithClient(host, "/.well-known/est", []string{"https"}, tc)
		ts.Consumers["application/pkcs7-mime"] = runtime.TextConsumer()
		ts.Producers["application/pkcs10"] = runtime.TextProducer()
		c := client.New(ts, strfmt.Default)

		p := operation.NewGetCACertsParams()

		var resp *operation.GetCACertsOK

		if retry {
			for {
				if resp, err = c.Operation.GetCACerts(p); err != nil {
					glog.Error(err)
					time.Sleep(5 * time.Second)
					continue
				}
				break
			}
		} else {
			if resp, err = c.Operation.GetCACerts(p); err != nil {
				glog.Error(err)
				return
			}
		}

		fmt.Println(resp.Payload)
		fmt.Println(resp.ContentTransferEncoding)
		fmt.Println(resp.ContentType)
		return
	},
}

func init() {
	rootCmd.AddCommand(enrollCmd)

	// Here you will define your flags and configuration settings.
	enrollCmd.Flags().BoolVarP(&trustUnknownCA, "trust-unknown-ca", "k", false, "Trust the EST CA's root CA... needed unless you have added this to your OS TrustStore")

	enrollCmd.Flags().BoolVarP(&retry, "retry", "r", false, "Keep retrying till we succeed or timeout")

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// enrollCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// enrollCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
