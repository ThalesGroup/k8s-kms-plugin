# Thales eToken Fusion

This guide describe how to set up a Thales eToken Fusion with `k8s-kms-plugin` in a **non production environment**.

![](https://cpl.thalesgroup.com/sites/default/files/content/access-management/images/product-images/USB-CFusion-tokens.webp)

> Work in progress

sudo pkcs11-tool --module /usr/lib64/pkcs11/libeTPkcs11.so --token-label "My Token" --login --pin "0000000000" --label rsakey --id 1212abab --keypairgen --key-type rsa:2048

sudo pkcs11-tool --module /usr/lib64/pkcs11/libeTPkcs11.so --login --token-label "My Token" --pin "0000000000" -O