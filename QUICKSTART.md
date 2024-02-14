# Quick Start

## SoftHsm

Install the required packages :

```sh
# debian
sudo apt install softhsm2 opensc
# redhat
sudo yum install epel-release softhsm opensc
```

Setup for rootless usage :

```sh
sudo cp /etc/softhsm/softhsm2.conf $HOME
sudo chown $USER: $HOME/softhsm2.conf
echo 'export SOFTHSM2_CONF=$HOME/softhsm2.conf' >> $HOME/.bashrc
source $HOME/.bashrc
sudo usermod -aG softhsm $USER
```

**Logout and login**.

Create a token :

```sh
softhsm2-util --init-token --slot 0 --label mylabel --so-pin mysopin --pin mypin
```

Create the encryption key :

```sh
# for debian
export MODULE="/usr/lib/softhsm/libsofthsm2.so"
# for redhat
export MODULE="/usr/lib64/pkcs11/libsofthsm2.so"
# aes kek
pkcs11-tool --module $MODULE --token-label mylabel --pin mypin --keygen --key-type aes:16 --label aes0
```

Start the plugin :

```sh
SOCKET="/run/user/$(id -u $USER)/k8s-kms-plugin.sock"
# aes-gcm mode
k8s-kms-plugin serve --socket $SOCKET \
  --p11-lib $MODULE --p11-label mylabel --p11-pin mypin --p11-key-label aes0 \
  --enable-server
```

Start a K3S cluster with the proper KMS configuration in [encryption-conf.yaml](k8s/encryption-conf.yaml) :

```sh
curl -sfL https://get.k3s.io | sh -s - \
  --kube-apiserver-arg=encryption-provider-config=encryption-conf.yaml
```
