## k8s-kms-plugin serve

Handles Kubernetes KMS v2 requests

### Synopsis

Handles Kubernetes KMS v2 requests but do not support key rotation.
Use "k8s-kms-plugin serve rotation" subcommand to support key rotation.
Kubernetes KMS documentation: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#configuring-the-kms-provider-kms-v2

KMS v2 API: https://pkg.go.dev/k8s.io/kms@v0.33.3/apis/v2


```
k8s-kms-plugin serve [flags]
```

### Examples

```

Using flags and serving on unix socket (gRPC plaintext):
	k8s-kms-plugin 
	  serve \
		--log-level=info \
		--socket /run/user/1000/k8s-kms-plugin.sock \
		--p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
		--p11-label mylabel \
		--p11-pin mypin \
		--p11-key-label rsa0 \
		--algorithm rsa-oaep

Using both environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin serve --config my-kms-plugin-config.yaml

Using both CLI Flags, environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin --log-format=json serve --config my-kms-plugin-config.yaml

Using AES-CBC with HMAC authentication, using CKA_ID, using CLI flags and serving on unix socket:
	k8s-kms-plugin 
	  serve \
		--log-level=trace  \
		--socket /run/user/1000/k8s-kms-plugin.sock \
		--p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
		--p11-label mylabel \
		--p11-pin mypin \
		--kek-id 64636138353931326363356537313264 \
		--hmac-id 30663536623936326235663530363234 \
		--algorithm aes-cbc

```

### Options

```
      --algorithm string         Set the algorithm for encryption/decryption. Possible values: aes-gcm, aes-cbc, rsa-oaep. Env var: K8S_KMS_PLUGIN_SERVE_ALGORITHM (default "aes-gcm")
      --allow-any                Allow any device (accepts all ids/secrets). Env var: K8S_KMS_PLUGIN_SERVE_ALLOW_ANY
      --auto-create              Auto create the keys if needed. Env var: K8S_KMS_PLUGIN_SERVE_AUTO_CREATE.
      --ca-id string             Cert ID for CA Cert record. Env var: K8S_KMS_PLUGIN_SERVE_CA_ID (default "1c3d30d5-dfa8-4167-a9f9-2c768464181b")
      --disable-socket           Disable socket based server. Env var: K8S_KMS_PLUGIN_SERVE_DISABLE_SOCKET.
      --enable-server            Enable TLS based server. Env var: K8S_KMS_PLUGIN_SERVE_ENABLE_SERVER.
  -h, --help                     help for serve
      --hmac-id string           Key ID CKA_ID for KMS HMAC. Env var: K8S_KMS_PLUGIN_SERVE_HMAC_ID
      --host string              Hostname without port. Env var: K8S_KMS_PLUGIN_SERVE_HOST. (default "0.0.0.0")
      --kek-id string            Key ID CKA_ID for KMS KEK. Env var: K8S_KMS_PLUGIN_SERVE_KEK_ID
  -p, --native-path string       Path to key store for native provider(Files only). Env var: K8S_KMS_PLUGIN_SERVE_NATIVE_PATH. (default ".keys")
      --p11-hmac-label string    Key Label CKA_LABEL to use for sha based verifications. Env var: K8S_KMS_PLUGIN_SERVE_P11_HMAC_LABEL.
      --p11-key-label string     Key Label CKA_LABEL to use for encrypt/decrypt. Env var: K8S_KMS_PLUGIN_SERVE_P11_KEY_LABEL.
      --p11-label string         P11 token label. Env var: K8S_KMS_PLUGIN_SERVE_P11_TOKEN
      --p11-lib string           Path to p11 library/client. Env var: K8S_KMS_PLUGIN_SERVE_P11_LIB
      --p11-pin string           P11 Pin. Env var: K8S_KMS_PLUGIN_SERVE_P11_PIN
      --p11-slot int             P11 token slot. Env var: K8S_KMS_PLUGIN_SERVE_P11_SLOT
      --port uint16              TCP Port for gRPC service. Env var: K8S_KMS_PLUGIN_SERVE_PORT. (default 31400)
      --provider string          Provider. Possible values: p11, softhsm, luna, dpod. Env var: K8S_KMS_PLUGIN_SERVE_PROVIDER. (default "p11")
      --socket string            Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_SERVE_KEK_SOCKET (default "/tmp/run/hsm-plugin-server.sock")
      --tls-ca string            TLS CA cert. Env var: K8S_KMS_PLUGIN_SERVE_TLS_CA. (default "certs/ca.crt")
      --tls-certificate string   TLS server cert. Env var: K8S_KMS_PLUGIN_SERVE_TLS_CERTIFICATE (default "certs/tls.crt")
      --tls-key string           TLS server key. Env var: K8S_KMS_PLUGIN_SERVE_TLS_KEY (default "certs/tls.key")
```

### Options inherited from parent commands

```
      --config string       ConfigFile. Env var: K8S_KMS_PLUGIN_CONFIG_FILE (default "k8s-kms-plugin.config.yaml")
      --debug               Set logrus.SetLevel to "debug". This is equivalent to using --log-level=debug. Flags --log-level and --debug flag are mutually exclusive. Env var: K8S_KMS_PLUGIN_DEBUG.
      --log-format string   Logrus log output format. Possible values: text, json. Env var: K8S_KMS_PLUGIN_LOG_FORMAT (default "text")
      --log-level string    Set logrus.SetLevel. Possible values: trace, debug, info, warning, error, fatal and panic. Flags --log-level and --debug flag are mutually exclusive. Env var: K8S_KMS_PLUGIN_LOG_LEVEL. (default "info")
```

### SEE ALSO

* [k8s-kms-plugin](k8s-kms-plugin.md)	 - Thales KMS Server for K8S
* [k8s-kms-plugin serve rotation](k8s-kms-plugin_serve_rotation.md)	 - KEK Key rotation for KMS v2

###### Auto generated by spf13/cobra on 31-Jul-2025
