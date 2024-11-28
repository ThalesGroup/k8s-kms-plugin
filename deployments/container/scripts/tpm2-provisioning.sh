#!/usr/bin/env bash

mkdir -p "${TPM2_PKCS11_STORE}"
tpm2_ptool init --path="${TPM2_PKCS11_STORE}"
pkcs11-tool --module "${MODULE}" --slot-index "${TOKENSLOT}" --init-token --label "${TOKENLABEL}" --so-pin "${SOPIN}"
pkcs11-tool --module "${MODULE}" --init-pin --so-pin "${SOPIN}" --login --pin "${PIN}" --slot-index "${TOKENSLOT}"
tpm2_ptool addkey --algorithm aes256 --label "${TOKENLABEL}" --key-label "${AESKEYLABEL}" --userpin "${PIN}" --path "${TPM2_PKCS11_STORE}"
