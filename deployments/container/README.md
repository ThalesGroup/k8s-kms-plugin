# GUIDE

## ContainerfileSofthsm

## Build

```sh
podman build -f ContainerfileSofthsm -t localhost/thales-softhsm
```

## Run

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

# check token slots
pkcs11-tool --module $MODULE --list-token-slots
> Available slots:
> Slot 0 (0x264ae282): SoftHSM slot ID 0x264ae282
>   token label        : mylabel
>   token manufacturer : SoftHSM project
>   token model        : SoftHSM v2
>   token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
>   hardware version   : 2.6
>   firmware version   : 2.6
>   serial num         : 2e4e4036264ae282
>   pin min/max        : 4/255

# list keys
pkcs11-tool --module $MODULE --token-label ${TOKENLABEL} --pin ${PIN} -O
> Secret Key Object; AES length 16
> warning: PKCS11 function C_GetAttributeValue(VALUE) failed: rv = CKR_ATTRIBUTE_SENSITIVE (0x11)
> 
>   label:      aes0
>   Usage:      encrypt, decrypt, verify, wrap, unwrap
>   Access:     never extractable, local
> Private Key Object; RSA 
>   label:      rsa0
>   Usage:      decrypt, sign, unwrap
>   Access:     sensitive, always sensitive, never extractable, local
> Public Key Object; RSA 4096 bits
>   label:      rsa0
>   Usage:      encrypt, verify, wrap
>   Access:     local

```