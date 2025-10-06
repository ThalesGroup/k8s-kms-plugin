**DO NOT USE IN PRODUCTION**

For testing purpose only.

If you do not have certificates available for testing, use this script `generate-self-signed-cert.sh` to generate a dummy self-signed root CA, a client and a server certificates and corresponding private keys.

```
./generate-self-signed-cert.sh 

🔧 Generating root CA...
🔧 Generating server TLS certificate...
Certificate request self-signature ok
subject=CN = kms-server.local
🔧 Generating client TLS certificate for mTLS...
Certificate request self-signature ok
subject=CN = kms-client
✅ All certificates generated in ./certs:
ca.crt
ca.key
ca.srl
client.cnf
client.crt
client.csr
client.key
server.cnf
tls.crt
tls.csr
tls.key
```