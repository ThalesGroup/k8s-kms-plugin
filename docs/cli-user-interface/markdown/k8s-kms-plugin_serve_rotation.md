---
title: "k8s-kms-plugin serve rotation"
description: "KEK Key rotation for KMS v2"
weight: 90
generator: "k8s-kms-plugin docs -f markdown"
---

## k8s-kms-plugin serve rotation

KEK Key rotation for KMS v2

### Synopsis

Handles Kubernetes KMS v2 requests and support KEK key rotation with x1 old KEK key and x1 active KEK key.
"k8s-kms-pluginc serve rotation" is very similar to the "k8s-kms-plugin serve" command, but adds key rotation support.
Refer to the kubernetes KMS v2 documentation for more details about key rotation.
https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#developing-a-kms-plugin-gRPC-server-notes-kms-v2

KMS v2 API: https://pkg.go.dev/k8s.io/kms@v0.34.1/apis/v2

How --old-p11-key-id / --old-p11-key-label (and --old-p11-hmac-id / --old-p11-hmac-label) are resolved:
docs/cli-user-interface/cka-id-vs-cka-label.md


```
k8s-kms-plugin serve rotation [flags]
```

### Examples

```

Using flags and serving on unix socket (gRPC plaintext):
	k8s-kms-plugin \
	  serve \
		--log-level=trace \
		--socket /run/user/1000/k8s-kms-plugin.sock \
		--p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
		--p11-label mylabel \
		--p11-pin mypin \
		--p11-key-label rsa0 \
		--algorithm-family rsa-oaep \
		  rotation \
			--old-p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
			--old-p11-label mylabel \
			--old-p11-pin mypin \
			--old-p11-key-id 64636138353931326363356537313264 \
			--old-p11-hmac-id 30663536623936326235663530363234 \
			--old-algorithm-family aes-cbc

Using environment variables and configuration file:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin serve rotation --config my-kms-plugin-config.yaml

Using both CLI Flags, environment variables and configuration file and serving on unix socket:
	K8S_KMS_PLUGIN_SERVE_P11_PIN="mypin" k8s-kms-plugin --log-format=json serve rotation --config my-kms-plugin-config.yaml
	
```

### Options

```
  -h, --help                                   help for rotation
      --old-algorithm-family algorithmFamily   Encryption mechanism of the old KEK. Possible values: aes-gcm, aes-cbc, rsa-oaep, ml-kem. (default aes-gcm)
      --old-native-path string                 Native path for old KEK
      --old-p11-hmac-id string                 Key ID CKA_ID for old KEK HMAC
      --old-p11-hmac-label string              Key Label (CKA_LABEL) for the old KEK HMAC. The key must have a CKA_ID set on the HSM.
      --old-p11-key-id string                  Key ID CKA_ID for old KEK
      --old-p11-key-label string               Key Label (CKA_LABEL) for the old KEK. The key must have a CKA_ID set on the HSM.
      --old-p11-label string                   P11 token label for old KEK
      --old-p11-lib string                     Path to P11 library/client for old KEK
      --old-p11-pin string                     HSM PIN for old KEK. If omitted, prompted interactively (input hidden). Pass an empty string explicitly to use a no-PIN token.
      --old-p11-slot int                       P11 token slot for old KEK
      --old-provider string                    Provider for old KEK (default "p11")
      --old-socket string                      Unix socket path for old KEK
```

### Options inherited from parent commands

```
      --algorithm-family algorithmFamily   Encryption mechanism. Possible values: aes-gcm, aes-cbc, rsa-oaep, ml-kem. (default aes-gcm)
      --auto-create                        Auto create the keys if needed.
      --config string                      ConfigFile. Env var: K8S_KMS_PLUGIN_CONFIG_FILE (default "k8s-kms-plugin.config.yaml")
      --debug                              Set log level to "debug". This is equivalent to using --log-level=debug. Flags --log-level and --debug flag are mutually exclusive. Env var: K8S_KMS_PLUGIN_DEBUG.
      --log-format string                  Log output format. Possible values: text, json. Env var: K8S_KMS_PLUGIN_LOG_FORMAT (default "text")
      --log-level string                   Set log level. Possible values: trace, debug, info, warn, error, quiet. Flags --log-level and --debug flag are mutually exclusive. Env var: K8S_KMS_PLUGIN_LOG_LEVEL. (default "info")
  -p, --native-path string                 Path to key store for native provider(Files only). (default ".keys")
      --p11-hmac-id string                 Key ID CKA_ID for KMS HMAC.
      --p11-hmac-label string              Key Label (CKA_LABEL) for the HMAC key. The key must have a CKA_ID set on the HSM.
      --p11-key-id string                  Key ID CKA_ID for KMS KEK.
      --p11-key-label string               Key Label (CKA_LABEL) for the KMS KEK. The key must have a CKA_ID set on the HSM — it is stored as the KEK ID in Kubernetes etcd.
      --p11-label string                   P11 token label.
      --p11-lib string                     Path to p11 library/client.
      --p11-pin string                     HSM PIN. If omitted, prompted interactively (input hidden). Pass an empty string explicitly to use a no-PIN token.
      --p11-slot int                       P11 token slot.
      --provider string                    Provider. Possible values: p11, softhsm, luna, dpod. (default "p11")
      --socket string                      Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. (default "/tmp/run/hsm-plugin-server.sock")
```

### SEE ALSO

* [k8s-kms-plugin serve](k8s-kms-plugin_serve.md)	 - Handles Kubernetes KMS v2 requests

