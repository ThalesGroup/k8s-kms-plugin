# GUIDE

## Goreleaser

This image is used to build the k8s-kms-plugin binary, with a common build environment.

```sh
podman build -f ContainerfileGoreleaser -t localhost/thales-k8s-kms-plugin-build-goreleaser
```

## Softhsm

`thales-softhsm` is a rootless container to test the k8s-kms-plugin with SoftHSM. 

### Build

```sh
podman build -f ContainerfileSofthsm -t localhost/thales-softhsm
```

### Run

```sh
podman run -it --name thales-softhsm localhost/thales-softhsm bash
```

Inside the container :

```sh
# update your user env
SOPIN="mysopin"
PIN="mypin"
TOKENLABEL="mylabel"
TOKENSLOT=0
MODULE="/usr/lib/softhsm/libsofthsm2.so"
STORE=""
AESKEYLABEL="aes0"
HMACKEYLABEL="hmac0"
RSAKEYLABEL="rsa0"

# list keys
pkcs11-tool --module $MODULE --token-label ${TOKENLABEL} --pin ${PIN} -O
```

## Software TPM

`thales-swtpm` is a privileged container to test the k8s-kms-plugin with Software TPM v2.
Root mode is required because the daemon of tpm2-abrmd need to access to the host's systemd processes. 

### Build

```sh
sudo podman build -f ContainerfileSwtpm -t localhost/thales-swtpm
```

### Run

```sh
sudo podman run --privileged -it --name thales-swtpm localhost/thales-swtpm bash
```

Inside the container :

```sh
# list keys
pkcs11-tool --module $MODULE --token-label ${TOKENLABEL} --pin ${PIN} -O 2> /dev/null
```