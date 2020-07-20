// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/ca"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/utils"
	"io"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/operations"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/operations/operation"
)

//go:generate swagger generate server --target ../../../../k8s-kms-plugin --name EstServer --spec ../../../apis/kms/v1/est.yaml --model-package pkg/est/models --server-package pkg/est/restapi --exclude-main

func configureFlags(api *operations.EstServerAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
	// Make all necessary changes to the TLS configuration here.

}

var estCA *ca.P11

func configureAPI(api *operations.EstServerAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.ApplicationPkcs10Consumer = runtime.ConsumerFunc(func(r io.Reader, target interface{}) error {
		return errors.NotImplemented("applicationPkcs10 consumer has not yet been implemented")
	})

	api.ApplicationPkcs7MimeProducer = runtime.ProducerFunc(func(w io.Writer, data interface{}) error {
		return errors.NotImplemented("applicationPkcs7Mime producer has not yet been implemented")
	})
	api.TxtProducer = runtime.TextProducer()

	// Applies when the Authorization header is set with the Basic scheme
	if api.BasicAuthAuth == nil {
		api.BasicAuthAuth = func(user string, pass string) (interface{}, error) {
			return nil, errors.NotImplemented("basic auth  (basicAuth) has not yet been implemented")
		}
	}

	// Set your custom authorizer if needed. Default one is security.Authorized()
	// Expected interface runtime.Authorizer
	//
	// Example:
	// api.APIAuthorizer = security.Authorized()
	if api.OperationGetCACertsHandler == nil {
		api.OperationGetCACertsHandler = operation.GetCACertsHandlerFunc(func(params operation.GetCACertsParams) middleware.Responder {
			//return middleware.NotImplemented("operation operation.GetCACerts has not yet been implemented")
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

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {

}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {

}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}

func (s *Server) AddConfig(caa, key, cert string) (err error) {
	config := utils.GetCrypto11Config()
	if estCA, err = ca.NewP11EST(caa, key, cert, config); err != nil {
		return
	}

	return
}
