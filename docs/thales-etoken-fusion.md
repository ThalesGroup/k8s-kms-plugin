# Thales eToken Fusion

This guide describes how to set up a Thales eToken Fusion with `k8s-kms-plugin` in a **non production environment**.

![](https://cpl.thalesgroup.com/sites/default/files/content/access-management/images/product-images/USB-CFusion-tokens.webp)

> 🚧 Work in progress

## 2. Testbed Environment

Unless otherwise specified, the commands from this guide were tested on AlmaLinux 9.6 on an x86_64 platform.

```bash
cat /etc/os-release
NAME="AlmaLinux"
VERSION="9.6 (Sage Margay)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.6"
PLATFORM_ID="platform:el9"
PRETTY_NAME="AlmaLinux 9.6 (Sage Margay)"
ANSI_COLOR="0;34"
LOGO="fedora-logo-icon"
CPE_NAME="cpe:/o:almalinux:almalinux:9::baseos"
HOME_URL="https://almalinux.org/"
DOCUMENTATION_URL="https://wiki.almalinux.org/"
BUG_REPORT_URL="https://bugs.almalinux.org/"

ALMALINUX_MANTISBT_PROJECT="AlmaLinux-9"
ALMALINUX_MANTISBT_PROJECT_VERSION="9.6"
REDHAT_SUPPORT_PRODUCT="AlmaLinux"
REDHAT_SUPPORT_PRODUCT_VERSION="9.6"
SUPPORT_END=2032-06-01
```

## Create an RSA Keypair

```bash
sudo pkcs11-tool \
  --module /usr/lib64/pkcs11/libeTPkcs11.so \
  --token-label "My Token" \
  --login --pin "0000000000" \
  --label rsakey \
  --id 1212abab \
  --keypairgen \
  --key-type rsa:2048
```

List objects:

```bash
sudo pkcs11-tool \
  --module /usr/lib64/pkcs11/libeTPkcs11.so \
  --login --pin "0000000000" \
  --token-label "My Token" \
  --list-objects
```

```
Public Key Object; RSA 2048 bits
  label:      rsa00eToken
  ID:         1212abab
  Usage:      encrypt, verify, wrap
  Access:     local
  uri:        pkcs11:model=ID%20Prime%20MD;manufacturer=Gemalto;serial=1FE250E4F7CD47D9;token=My%20Token;id=%1212abab;object=rsa00eToken;type=public
Private Key Object; RSA 
  label:      rsa00eToken
  ID:         1212abab
  Usage:      decrypt, sign, unwrap
  Access:     sensitive, always sensitive, never extractable, local
  uri:        pkcs11:model=ID%20Prime%20MD;manufacturer=Gemalto;serial=1FE250E4F7CD47D9;token=My%20Token;id=%1212abab;object=rsa00eToken;type=private
```


## Start `k8s-kms-plugin` in `rsa-oaep` mode

```bash
sudo k8s-kms-plugin \
    serve \
      --log-level=trace \
      --socket /run/user/1000/k8s-kms-plugin.sock \
      --p11-lib /usr/lib64/pkcs11/libeTPkcs11.so \
      --p11-label "My Token" \
      --p11-pin "0000000000" \
      --kek-id 1212abab \
      --algorithm rsa-oaep
```

You can validate Encryption and Decryption are working by using [`grpcurl-roundtrip-test.sh`](../scripts/grpcurl/grpcurl-roundtrip-test.sh).