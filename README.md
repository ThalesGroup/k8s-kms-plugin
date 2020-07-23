# K8S-KMS-Plugin

This microservice implements the Kubernetes KMS protocol as a gRPC service that leverages a remote or local HSM via PKCS11.

This plugin will also run in proxy mode which can connect to a remote plugin service running in a secure network device (Key Managers)

## requirements

This service is designed for kubernetes clusters that are using version 1.10.0 or higher and implements the KMS API:

https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/

So for development purposes, you'll want a cluster that can be configured to use a KMS gRPC endpoint on your APIServer nodes. 

## Deployment scenarios

This plugin is designed to be deployed in 2 configurations

- StandAlone - Plugin and PKCS11 library deployed as StaticPod/HostContainer on APIServer nodes
- Client/Server - k8s-kms-plugin in `client` mode will `enroll` to an external k8s-kms-plugin running in `serve` mode

## How to develop

This project is a collection


