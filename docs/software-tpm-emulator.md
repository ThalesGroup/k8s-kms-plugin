# [`Software TPM Emulator`](https://github.com/stefanberger/swtpm)

> ⚠️ **Legacy reference**: This guide is kept for backward compatibility. [`SoftHSMv3` (`pqctoday-hsm`)](./softhsm-v3.md) is now the recommended software HSM for development and integration testing — it supports all algorithm families including **ML-KEM**. The Software TPM Emulator does **not** support ML-KEM.

This guide described how to set up [`Software TPM Emulator`](https://github.com/stefanberger/swtpm) and make it work with the `k8s-kms-plugin` in a **non production environment**.

You should read [`Software TPM Emulator`](https://github.com/stefanberger/swtpm) official documentation before reading this guide.

- [Install `Software TPM Emulator`](#install-software-tpm-emulator)
- [Create Keys in the `Software TPM Emulator`](#create-keys-in-the-software-tpm-emulator)
  - [AES CBC HMAC](#aes-cbc-hmac)
    - [Create an AES \& an HMAC Key](#create-an-aes--an-hmac-key)
    - [Run `k8s-kms-plugin serve` with `aes-cbc`](#run-k8s-kms-plugin-serve-with-aes-cbc)
  - [RSA-OAEP](#rsa-oaep)
    - [Create an RSA Keypair](#create-an-rsa-keypair)
    - [Run `k8s-kms-plugin serve` with `rsa-oaep`](#run-k8s-kms-plugin-serve-with-rsa-oaep)


## Install `Software TPM Emulator`

Outside of the scope of this documentation.

## Create Keys in the `Software TPM Emulator`

You must know that AES GCM is not supported by the TPM v2 specifications.
With `Software TPM Emulator`, we recommend to run the `k8s-kms-plugin` with the CBC-then-HMAC algorithm or an RSA-OAEP key.

### AES CBC HMAC

#### Create an AES & an HMAC Key

List your AES & an HMAC keys:

```bash
pkcs11-tool \
  --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
  --login --pin "mypin" \
  --token-label "mylabel" \
  --list-objects
```
```
Secret Key Object; unknown key algorithm 43
  label:      hmac0
  ID:         30663536623936326235663530363234
  Usage:      verify
  Access:     sensitive, always sensitive, never extractable, local
Secret Key Object; AES length 32
WARNING: Needed CKA_VALUE but didn't find encrypted blob
WARNING: Needed CKA_VALUE but didn't find encrypted blob
  VALUE:      
  label:      aes0
  ID:         64636138353931326363356537313264
  Usage:      encrypt, decrypt
  Access:     sensitive, always sensitive, never extractable, local
```

> On debian, you can find
> 
> ```bash
> dpkg -L libtpm2-pkcs11-1 | grep '\.so$'
> /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so
> ```

#### Run `k8s-kms-plugin serve` with `aes-cbc`

You must provide an HMAC key alongside the AES key for encryption:

```sh
# debian
export MODULE="/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1"
# redhat
export MODULE="/usr/lib64/pkcs11/libtpm2_pkcs11.so"
# serve
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --provider p11 \
    --p11-lib $MODULE \
    --p11-key-label aes0 \
    --p11-hmac-label hmac0 \
    --p11-label mylabel \
    --p11-pin mypin \
    --algorithm-family aes-cbc
```

Alternatively, you can use `--p11-key-id` (PKCS #11 CKA_ID) instead of `--p11-key-label` (PKCS #11 CKA_LABEL).
See [`CKA_ID` vs `CKA_LABEL`](./cli-user-interface/cka-id-vs-cka-label.md) for how the two are resolved.

```bash
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --p11-lib  /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1  \
    --p11-label mylabel  \
    --p11-pin  mypin  \
    --p11-key-id  64636138353931326363356537313264 \
    --p11-hmac-id 30663536623936326235663530363234 \
    --algorithm-family aes-cbc \
    --socket /run/user/1000/k8s-kms-plugin.sock
```


You can validate Encryption and Decryption are working by using [`grpcurl-roundtrip-test.sh`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/scripts/grpcurl/grpcurl-roundtrip-test.sh).

```bash
./grpcurl-roundtrip-test.sh 'hello world' /run/user/1000/k8s-kms-plugin.sock
```

### RSA-OAEP

#### Create an RSA Keypair

List

```bash
pkcs11-tool \
  --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
  --login --pin "mypin" \
  --token-label "mylabel" \
  --list-objects
```
```
Public Key Object; RSA 2048 bits
  label:      rsa0
  ID:         123abc
  Usage:      encrypt, verify
  Access:     local
Private Key Object; RSA 
  label:      rsa0
  ID:         123abc
  Usage:      decrypt, sign
  Access:     sensitive, always sensitive, never extractable, local
  Allowed mechanisms: RSA-X-509,RSA-PKCS-OAEP,RSA-PKCS,SHA1-RSA-PKCS,SHA256-RSA-PKCS,SHA384-RSA-PKCS,SHA512-RSA-PKCS,RSA-PKCS-PSS,SHA1-RSA-PKCS-PSS,SHA256-RSA-PKCS-PSS,SHA384-RSA-PKCS-PSS,SHA512-RSA-PKCS-PSS
```

#### Run `k8s-kms-plugin serve` with `rsa-oaep`

```bash
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket /run/user/1000/k8s-kms-plugin.sock \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mylabel \
    --p11-pin mypin \
    --p11-key-label rsa0 \
    --algorithm-family rsa-oaep
```

You can validate Encryption and Decryption are working by using [`grpcurl-roundtrip-test.sh`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/scripts/grpcurl/grpcurl-roundtrip-test.sh).