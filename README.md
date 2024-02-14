# K8S-KMS-Plugin

This microservice implements the Kubernetes KMS protocol as a gRPC service that leverages a remote or local HSM via PKCS11.

This plugin will also run in proxy mode which can connect to a remote plugin service running in a secure network device (Key Managers)

## requirements

This service is designed for kubernetes clusters that are using version 1.10.0 or higher and implements the KMS API:

https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/

So for development purposes, you'll want a cluster that can be configured to use a KMS gRPC endpoint on your APIServer nodes.

To serve the k8s-kms-plugin for encryption operations from Kubernetes, you will need at least one AES key in a PKCS11 provider.

## KMS provider for SoftHsm V2

In this mode, we recommend to run the k8s-kms-plugin with the GCM algorithm.  
It provides a better design for authenticated encryption operations :

```sh
# debian
export MODULE="/usr/lib/softhsm/libsofthsm2.so"
# redhat
export MODULE="/usr/lib64/pkcs11/libsofthsm2.so"
# serve
k8s-kms-plugin serve \
  --provider p11 --p11-lib $MODULE --p11-key-label mykey --p11-label mylabel --p11-pin mypin --enable-server
```

## KMS provider for TPM2 PKCS11

You must know that AES GCM is not supported by the TPM v2 specifications.
In this mode, we recommend to run the k8s-kms-plugin with the CBC-then-HMAC algorithm. 
You must provide an HMAC key alongside the AES key for encryption :

```sh
# debian
export MODULE="/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1"
# redhat
export MODULE="/usr/lib64/pkcs11/libtpm2_pkcs11.so"
# serve
k8s-kms-plugin serve \
  --provider p11 --p11-lib $MODULE --p11-key-label cbc0 --p11-hmac-label hmac0 --p11-label mylabel --p11-pin mypin --algorithm aes-cbc --enable-server
```

## Quick Start

Read the [QUICKSTART.md](QUICKSTART.md).

## Deployment scenarios

This plugin is designed to be deployed in 2 configurations

- Client/Server - k8s-kms-plugin in `client` mode will `enroll` to an external k8s-kms-plugin running in `serve` mode
- StandAlone(TODO) - Plugin and PKCS11 library deployed as StaticPod/HostContainer on APIServer nodes, this will require
coordination with k8s provisioning tools.

## Development Environment

`k8s` houses some sample client and server deployments for e2e testing until such time as this plugin is 100% network functional,
 and we can move it to a CICD pattern, as we'll have many actors to coordinate. 

All apis are defined in the `/apis` dir, and as we iterate on the spec docs, one must then run `make gen` and refactor 
until the 2 stacks come up

Both EST and KMS-Plugin binaries are in the `/cmd` dir
 
The `Makefile` contains commands for easy execution:
- `make gen` - generates all apis into gRPC or OpenAPI Servers and Clients
- `make dev` - loads project into your kubernetes cluster (minikube or GKE will work just fine), and continously builds and deploys as you develop.
- `make build` - builds the standalone `k8s-kms-plugin` binary

## Debug Environment

For a remote debug, build the plugin with debug mode :

```sh
go get github.com/go-delve/delve/cmd/dlv
make build-debug
```

It will generate a binary `k8s-kms-plugin` that can be used with Delve for debug purpose.  
Do not use this binary in a production environment.

## Vulnerability check

```sh
$ govulncheck ./...
Scanning your code and 288 packages across 34 dependent modules for known vulnerabilities...

No vulnerabilities found.
```


