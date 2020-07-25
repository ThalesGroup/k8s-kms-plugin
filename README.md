# K8S-KMS-Plugin

This microservice implements the Kubernetes KMS protocol as a gRPC service that leverages a remote or local HSM via PKCS11.

This plugin will also run in proxy mode which can connect to a remote plugin service running in a secure network device (Key Managers)

## requirements

This service is designed for kubernetes clusters that are using version 1.10.0 or higher and implements the KMS API:

https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/

So for development purposes, you'll want a cluster that can be configured to use a KMS gRPC endpoint on your APIServer nodes. 

Locally you should install [skaffold.dev](https://skaffold.dev) tooling as well as Cloud Code in your favorite IDE to leverage the skaffold.yaml file in this repo.

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


NOTE:  Currently the standalone plugin just waits for the 