# [`Software TPM Emulator`](https://github.com/stefanberger/swtpm)

This guide described how to set up [`Software TPM Emulator`](https://github.com/stefanberger/swtpm) and make it work with the `k8s-kms-plugin` in a **non production environment**.

You should read [`Software TPM Emulator`](https://github.com/stefanberger/swtpm) official documentation before reading this guide.

- [1. Install `Software TPM Emulator`](#1-install-software-tpm-emulator)
- [2. Create Keys in the `Software TPM Emulator`](#2-create-keys-in-the-software-tpm-emulator)
  - [2.1. AES CBC HMAC](#21-aes-cbc-hmac)
    - [2.1.1. Create an AES \& an HMAC Key](#211-create-an-aes--an-hmac-key)
    - [2.1.2. Run `k8s-kms-plugin serve` with `aes-cbc`](#212-run-k8s-kms-plugin-serve-with-aes-cbc)
  - [2.2. RSA-OAEP](#22-rsa-oaep)
    - [2.2.1. Create an RSA Keypair](#221-create-an-rsa-keypair)
    - [2.2.2. Run `k8s-kms-plugin serve` with `rsa-oaep`](#222-run-k8s-kms-plugin-serve-with-rsa-oaep)


## 1. Install `Software TPM Emulator`

Outside of the scope of this documentation.

## 2. Create Keys in the `Software TPM Emulator`

You must know that AES GCM is not supported by the TPM v2 specifications.
With `Software TPM Emulator`, we recommend to run the `k8s-kms-plugin` with the CBC-then-HMAC algorithm or an RSA-OAEP key.

### 2.1. AES CBC HMAC

#### 2.1.1. Create an AES & an HMAC Key

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

#### 2.1.2. Run `k8s-kms-plugin serve` with `aes-cbc`

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
    --algorithm aes-cbc
```

Alternatively, you can use `--kek-id` (PKCS #11 CKA_ID) instead of `--p11-key-label` (PKCS #11 CKA_LABEL).

```bash
k8s-kms-plugin 
  serve \
    --log-level=trace \
    --p11-lib  /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1  \
    --p11-label mylabel  \
    --p11-pin  mypin  \
    --kek-id  64636138353931326363356537313264 \
    --hmac-id 30663536623936326235663530363234 \
    --algorithm aes-cbc \
    --socket /run/user/1000/k8s-kms-plugin.sock
```


You can validate Encryption and Decryption are working by using [`grpcurl-roundtrip-test.sh`](../scripts/grpcurl/grpcurl-roundtrip-test.sh).

```bash
./grpcurl-roundtrip-test.sh 'hello world' /run/user/1000/k8s-kms-plugin.sock
```

### 2.2. RSA-OAEP

#### 2.2.1. Create an RSA Keypair

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

#### 2.2.2. Run `k8s-kms-plugin serve` with `rsa-oaep`

```bash
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket /run/user/1000/k8s-kms-plugin.sock \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mylabel \
    --p11-pin mypin \
    --p11-key-label rsa0 \
    --algorithm rsa-oaep
```

You can validate Encryption and Decryption are working by using [`grpcurl-roundtrip-test.sh`](../scripts/grpcurl/grpcurl-roundtrip-test.sh).