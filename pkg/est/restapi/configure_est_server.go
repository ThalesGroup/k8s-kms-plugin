// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"github.com/go-openapi/swag"
	"github.com/sirupsen/logrus"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/ca"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/producers"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/utils"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/operations"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/operations/operation"
)

var estCA *ca.P11
var extraFlags struct {
	AllowAnyDevice bool   `long:"allow-any" description:"Allow any device (accepts all ids/secrets)"`
	AuthFile       string `long:"auth-file" description:"CSV file containing device ids and credentials" required:"false"`
	EstCaCertFile  string `long:"est-cert" description:"EST CA certificate file (PEM format)" required:"false"`
	EstCaKeyID     string `long:"est-kid" description:"EST CA KID in PKCS11 Device" required:"false"`
	//EstCaKeyFile     string `long:"est-key" description:"EST CA signing key (PEM format, RSA only)" required:"false"`
}

//go:generate swagger generate server --target ../../../../k8s-kms-plugin --name EstServer --spec ../../../apis/kms/v1/est.yaml --model-package pkg/est/models --server-package pkg/est/restapi --exclude-main
func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
}

func configureAPI(api *operations.EstServerAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError
	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf
	api.ApplicationPkcs7MimeProducer = producers.PKCS7Producer()
	api.Logger = logrus.Infof
	api.TxtProducer = runtime.TextProducer()

	// Applies when the Authorization header is set with the Basic scheme
	logrus.Infof("extraFlags: %v", extraFlags)

	api.BasicAuthAuth = func(s string, s2 string) (interface{}, error) {
		logrus.Infof("What?")

		return s, nil
	}
	// Set your custom authorizer if needed. Default one is security.Authorized()
	// Expected interface runtime.Authorizer
	//
	// Example:
	// api.APIAuthorizer = security.Authorized()
	if api.OperationGetCACertsHandler == nil {
		api.OperationGetCACertsHandler = operation.GetCACertsHandlerFunc(func(params operation.GetCACertsParams) middleware.Responder {
			logrus.Infof("What?")

			return estCA.GetCACerts(params)
		})
	}
	if api.OperationSimpleenrollHandler == nil {
		api.OperationSimpleenrollHandler = operation.SimpleenrollHandlerFunc(func(params operation.SimpleenrollParams, principal interface{}) middleware.Responder {
			return estCA.SimpleEnroll(params, principal)
		})
	}
	if api.OperationSimplereenrollHandler == nil {
		api.OperationSimplereenrollHandler = operation.SimplereenrollHandlerFunc(func(params operation.SimplereenrollParams) middleware.Responder {
			return estCA.SimpleReenroll(params)
		})
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// configureFlags adds custom flags to the server.
func configureFlags(api *operations.EstServerAPI) {
	api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{
		swag.CommandLineOptionsGroup{
			ShortDescription: "Service Configuration",
			Options:          &extraFlags,
		},
	}

}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {

}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {

	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven

	tlsConfig.Certificates = []tls.Certificate{*estCA.ServerCert}
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

func (s *Server) LoadCA() (err error) {
	config := utils.GetCrypto11Config()
	if estCA, err = ca.NewP11EST(extraFlags.EstCaCertFile, string(s.TLSCertificateKey), string(s.TLSCertificate), extraFlags.EstCaKeyID, config); err != nil {
		return
	}
	return estCA.LoadCA()

}
