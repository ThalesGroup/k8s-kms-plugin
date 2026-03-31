| Command | Flags (long) | Flags (short) | Env Var | Config File Keys | Default Value | Type | Persistent Flag | Usage |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| k8s-kms-plugin | --config |  | K8S_KMS_PLUGIN_CONFIG | k8s-kms-plugin.config | k8s-kms-plugin.config.yaml | string | true | ConfigFile. Env var: K8S_KMS_PLUGIN_CONFIG_FILE |
| k8s-kms-plugin | --debug |  | K8S_KMS_PLUGIN_DEBUG | k8s-kms-plugin.debug | false | bool | true | Set logrus.SetLevel to "debug". This is equivalent to using --log-level=debug. Flags --log-level and --debug flag are mutually exclusive. Env var: K8S_KMS_PLUGIN_DEBUG. |
| k8s-kms-plugin | --log-format |  | K8S_KMS_PLUGIN_LOG_FORMAT | k8s-kms-plugin.log-format | text | string | true | Logrus log output format. Possible values: text, json. Env var: K8S_KMS_PLUGIN_LOG_FORMAT |
| k8s-kms-plugin | --log-level |  | K8S_KMS_PLUGIN_LOG_LEVEL | k8s-kms-plugin.log-level | info | string | true | Set logrus.SetLevel. Possible values: trace, debug, info, warning, error, fatal and panic. Flags --log-level and --debug flag are mutually exclusive. Env var: K8S_KMS_PLUGIN_LOG_LEVEL. |
| k8s-kms-plugin decrypt-csr | --input-filename | -f | K8S_KMS_PLUGIN_DECRYPT_CSR_INPUT_FILENAME | k8s-kms-plugin.decrypt-csr.input-filename |  | string | false | Input file. Env var: K8S_KMS_PLUGIN_DECRYPT_CSR_INPUT_FILE |
| k8s-kms-plugin decrypt-csr | --output-filename | -o | K8S_KMS_PLUGIN_DECRYPT_CSR_OUTPUT_FILENAME | k8s-kms-plugin.decrypt-csr.output-filename |  | string | false | Output file. Env var: K8S_KMS_PLUGIN_DECRYPT_CSR_OUTPUT_FILE |
| k8s-kms-plugin decrypt-csr | --socket |  | K8S_KMS_PLUGIN_DECRYPT_CSR_SOCKET | k8s-kms-plugin.decrypt-csr.socket | /tmp/run/hsm-plugin-server.sock | string | false | Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_DECRYPT_CSR_SOCKET |
| k8s-kms-plugin decrypt-csr | --timeout |  | K8S_KMS_PLUGIN_DECRYPT_CSR_TIMEOUT | k8s-kms-plugin.decrypt-csr.timeout | 30s | duration | false | KMS timeout. Env var: K8S_KMS_PLUGIN_DECRYPT_CSR_TIMEOUT |
| k8s-kms-plugin docs | --format | -f | K8S_KMS_PLUGIN_DOCS_FORMAT | k8s-kms-plugin.docs.format | markdown | string | false | Docs Output format. Prefered is markdown. Supported formats: markdown, man, rst, yaml, cli-table-csv, cli-table-pretty, cli-table-html, all. |
| k8s-kms-plugin docs | --help | -h | K8S_KMS_PLUGIN_DOCS_HELP | k8s-kms-plugin.docs.help | false | bool | false | help for docs |
| k8s-kms-plugin docs | --output-dir | -o | K8S_KMS_PLUGIN_DOCS_OUTPUT_DIR | k8s-kms-plugin.docs.output-dir | /tmp/k8s-kms-plugin-docs-2025-10-07T16:43:47+02:00 | string | false | Output directory |
| k8s-kms-plugin generate-kek | --kek-id |  | K8S_KMS_PLUGIN_GENERATE_KEK_KEK_ID | k8s-kms-plugin.generate-kek.kek-id | a37807cd-6d1a-4d75-813a-e120f30176f7 | string | false | Key ID for KMS KEK. Env var: K8S_KMS_PLUGIN_GENERATE_KEK_KEK_ID |
| k8s-kms-plugin generate-kek | --socket |  | K8S_KMS_PLUGIN_GENERATE_KEK_SOCKET | k8s-kms-plugin.generate-kek.socket | /tmp/run/hsm-plugin-server.sock | string | false | Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_GENERATE_KEK_SOCKET |
| k8s-kms-plugin generate-kek | --timeout |  | K8S_KMS_PLUGIN_GENERATE_KEK_TIMEOUT | k8s-kms-plugin.generate-kek.timeout | 30s | duration | false | KMS timeout. Env var: K8S_KMS_PLUGIN_GENERATE_KEK_TIMEOUT |
| k8s-kms-plugin import-ca | --cert-file | -f | K8S_KMS_PLUGIN_IMPORT_CA_CERT_FILE | k8s-kms-plugin.import-ca.cert-file |  | string | false | Certificate File. Env var: K8S_KMS_PLUGIN_IMPORT_CA_CERT_FILE |
| k8s-kms-plugin import-ca | --socket |  | K8S_KMS_PLUGIN_IMPORT_CA_SOCKET | k8s-kms-plugin.import-ca.socket | /tmp/run/hsm-plugin-server.sock | string | false | Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_IMPORT_CA_SOCKET |
| k8s-kms-plugin import-ca | --timeout |  | K8S_KMS_PLUGIN_IMPORT_CA_TIMEOUT | k8s-kms-plugin.import-ca.timeout | 30s | duration | false | KMS timeout. Env var: K8S_KMS_PLUGIN_IMPORT_CA_TIMEOUT |
| k8s-kms-plugin serve | --algorithm |  | K8S_KMS_PLUGIN_SERVE_ALGORITHM | k8s-kms-plugin.serve.algorithm | aes-gcm | string | true | Set the algorithm for encryption/decryption. Possible values: aes-gcm, aes-cbc, rsa-oaep. |
| k8s-kms-plugin serve | --allow-any |  | K8S_KMS_PLUGIN_SERVE_ALLOW_ANY | k8s-kms-plugin.serve.allow-any | false | bool | true | Allow any device (accepts all ids/secrets). |
| k8s-kms-plugin serve | --auto-create |  | K8S_KMS_PLUGIN_SERVE_AUTO_CREATE | k8s-kms-plugin.serve.auto-create | false | bool | true | Auto create the keys if needed. |
| k8s-kms-plugin serve | --ca-id |  | K8S_KMS_PLUGIN_SERVE_CA_ID | k8s-kms-plugin.serve.ca-id | 1c3d30d5-dfa8-4167-a9f9-2c768464181b | string | true | Cert ID for CA Cert record. |
| k8s-kms-plugin serve | --disable-socket |  | K8S_KMS_PLUGIN_SERVE_DISABLE_SOCKET | k8s-kms-plugin.serve.disable-socket | false | bool | true | Disable socket based server. |
| k8s-kms-plugin serve | --enable-server |  | K8S_KMS_PLUGIN_SERVE_ENABLE_SERVER | k8s-kms-plugin.serve.enable-server | false | bool | true | Enable TLS based server. |
| k8s-kms-plugin serve | --host |  | K8S_KMS_PLUGIN_SERVE_HOST | k8s-kms-plugin.serve.host | 0.0.0.0 | string | true | Hostname without port. |
| k8s-kms-plugin serve | --native-path | -p | K8S_KMS_PLUGIN_SERVE_NATIVE_PATH | k8s-kms-plugin.serve.native-path | .keys | string | true | Path to key store for native provider(Files only). |
| k8s-kms-plugin serve | --p11-hmac-id |  | K8S_KMS_PLUGIN_SERVE_P11_HMAC_ID | k8s-kms-plugin.serve.p11-hmac-id |  | string | true | Key ID CKA_ID for KMS HMAC. |
| k8s-kms-plugin serve | --p11-hmac-label |  | K8S_KMS_PLUGIN_SERVE_P11_HMAC_LABEL | k8s-kms-plugin.serve.p11-hmac-label |  | string | true | Key Label CKA_LABEL to use for sha based verifications. |
| k8s-kms-plugin serve | --p11-key-id |  | K8S_KMS_PLUGIN_SERVE_P11_KEY_ID | k8s-kms-plugin.serve.p11-key-id |  | string | true | Key ID CKA_ID for KMS KEK. |
| k8s-kms-plugin serve | --p11-key-label |  | K8S_KMS_PLUGIN_SERVE_P11_KEY_LABEL | k8s-kms-plugin.serve.p11-key-label |  | string | true | Key Label CKA_LABEL to use for encrypt/decrypt. |
| k8s-kms-plugin serve | --p11-label |  | K8S_KMS_PLUGIN_SERVE_P11_LABEL | k8s-kms-plugin.serve.p11-label |  | string | true | P11 token label. |
| k8s-kms-plugin serve | --p11-lib |  | K8S_KMS_PLUGIN_SERVE_P11_LIB | k8s-kms-plugin.serve.p11-lib |  | string | true | Path to p11 library/client. |
| k8s-kms-plugin serve | --p11-pin |  | K8S_KMS_PLUGIN_SERVE_P11_PIN | k8s-kms-plugin.serve.p11-pin |  | string | true | P11 Pin. |
| k8s-kms-plugin serve | --p11-slot |  | K8S_KMS_PLUGIN_SERVE_P11_SLOT | k8s-kms-plugin.serve.p11-slot | 0 | int | true | P11 token slot. |
| k8s-kms-plugin serve | --port |  | K8S_KMS_PLUGIN_SERVE_PORT | k8s-kms-plugin.serve.port | 31400 | uint16 | true | TCP Port for gRPC service. |
| k8s-kms-plugin serve | --provider |  | K8S_KMS_PLUGIN_SERVE_PROVIDER | k8s-kms-plugin.serve.provider | p11 | string | true | Provider. Possible values: p11, softhsm, luna, dpod. |
| k8s-kms-plugin serve | --socket |  | K8S_KMS_PLUGIN_SERVE_SOCKET | k8s-kms-plugin.serve.socket | /tmp/run/hsm-plugin-server.sock | string | true | Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. |
| k8s-kms-plugin serve | --tls-ca |  | K8S_KMS_PLUGIN_SERVE_TLS_CA | k8s-kms-plugin.serve.tls-ca | certs/ca.crt | string | true | TLS CA cert. |
| k8s-kms-plugin serve | --tls-certificate |  | K8S_KMS_PLUGIN_SERVE_TLS_CERTIFICATE | k8s-kms-plugin.serve.tls-certificate | certs/tls.crt | string | true | TLS server cert. |
| k8s-kms-plugin serve | --tls-key |  | K8S_KMS_PLUGIN_SERVE_TLS_KEY | k8s-kms-plugin.serve.tls-key | certs/tls.key | string | true | TLS server key. |
| k8s-kms-plugin serve rotation | --old-algorithm |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_ALGORITHM | k8s-kms-plugin.serve.rotation.old-algorithm |  | string | false | Set the algorithm for the old KEK |
| k8s-kms-plugin serve rotation | --old-ca-id |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_CA_ID | k8s-kms-plugin.serve.rotation.old-ca-id |  | string | false | Cert ID for old CA Cert record |
| k8s-kms-plugin serve rotation | --old-native-path |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_NATIVE_PATH | k8s-kms-plugin.serve.rotation.old-native-path |  | string | false | Native path for old KEK |
| k8s-kms-plugin serve rotation | --old-p11-hmac-id |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_HMAC_ID | k8s-kms-plugin.serve.rotation.old-p11-hmac-id |  | string | false | Key ID CKA_ID for old KEK HMAC |
| k8s-kms-plugin serve rotation | --old-p11-hmac-label |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_HMAC_LABEL | k8s-kms-plugin.serve.rotation.old-p11-hmac-label |  | string | false | Key Label CKA_LABEL for old KEK HMAC |
| k8s-kms-plugin serve rotation | --old-p11-key-id |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_KEY_ID | k8s-kms-plugin.serve.rotation.old-p11-key-id |  | string | false | Key ID CKA_ID for old KEK |
| k8s-kms-plugin serve rotation | --old-p11-key-label |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_KEY_LABEL | k8s-kms-plugin.serve.rotation.old-p11-key-label |  | string | false | Key Label CKA_LABEL for old KEK |
| k8s-kms-plugin serve rotation | --old-p11-label |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_LABEL | k8s-kms-plugin.serve.rotation.old-p11-label |  | string | false | P11 token label for old KEK |
| k8s-kms-plugin serve rotation | --old-p11-lib |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_LIB | k8s-kms-plugin.serve.rotation.old-p11-lib |  | string | false | Path to P11 library/client for old KEK |
| k8s-kms-plugin serve rotation | --old-p11-pin |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_PIN | k8s-kms-plugin.serve.rotation.old-p11-pin |  | string | false | P11 Pin for old KEK |
| k8s-kms-plugin serve rotation | --old-p11-slot |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_P11_SLOT | k8s-kms-plugin.serve.rotation.old-p11-slot | 0 | int | false | P11 token slot for old KEK |
| k8s-kms-plugin serve rotation | --old-provider |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_PROVIDER | k8s-kms-plugin.serve.rotation.old-provider | p11 | string | false | Provider for old KEK |
| k8s-kms-plugin serve rotation | --old-socket |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_SOCKET | k8s-kms-plugin.serve.rotation.old-socket |  | string | false | Unix socket path for old KEK |
| k8s-kms-plugin serve rotation | --old-tls-ca |  | K8S_KMS_PLUGIN_SERVE_ROTATION_OLD_TLS_CA | k8s-kms-plugin.serve.rotation.old-tls-ca |  | string | false | TLS CA cert for old KEK |
| k8s-kms-plugin test | --loop |  | K8S_KMS_PLUGIN_TEST_LOOP | k8s-kms-plugin.test.loop | false | bool | false | Should we run the test in a loop? Env var: K8S_KMS_PLUGIN_TEST_LOOP |
| k8s-kms-plugin test | --loop-sleep |  | K8S_KMS_PLUGIN_TEST_LOOP_SLEEP | k8s-kms-plugin.test.loop-sleep | 10s | duration | false | How many seconds to sleep between test runs. Env var: K8S_KMS_PLUGIN_TEST_LOOP_SLEEP |
| k8s-kms-plugin test | --max-loops |  | K8S_KMS_PLUGIN_TEST_MAX_LOOPS | k8s-kms-plugin.test.max-loops | 100 | int | false | How many seconds to sleep between test runs. Env var: K8S_KMS_PLUGIN_TEST_LOOP_SLEEP |
| k8s-kms-plugin test | --socket |  | K8S_KMS_PLUGIN_TEST_SOCKET | k8s-kms-plugin.test.socket | /tmp/run/hsm-plugin-server.sock | string | false | Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_TEST_SOCKET |
| k8s-kms-plugin test | --timeout |  | K8S_KMS_PLUGIN_TEST_TIMEOUT | k8s-kms-plugin.test.timeout | 30s | duration | false | KMS timeout. Env var: K8S_KMS_PLUGIN_TEST_TIMEOUT |
| k8s-kms-plugin verify-cert | --cert-file | -f | K8S_KMS_PLUGIN_VERIFY_CERT_CERT_FILE | k8s-kms-plugin.verify-cert.cert-file |  | string | false | Cert Chain File. Env var: K8S_KMS_PLUGIN_VERIFY_CERT_FILE |
| k8s-kms-plugin verify-cert | --socket |  | K8S_KMS_PLUGIN_VERIFY_CERT_SOCKET | k8s-kms-plugin.verify-cert.socket | /tmp/run/hsm-plugin-server.sock | string | false | Unix Socket. Example: /run/user/$(id -u $USER)/k8s-kms-plugin.sock. Env var: K8S_KMS_PLUGIN_VERIFY_CERT_SOCKET |
| k8s-kms-plugin verify-cert | --timeout |  | K8S_KMS_PLUGIN_VERIFY_CERT_TIMEOUT | k8s-kms-plugin.verify-cert.timeout | 10s | duration | false | KMS timeout. Env var: K8S_KMS_PLUGIN_VERIFY_CERT_TIMEOUT |
| k8s-kms-plugin version | --output | -o | K8S_KMS_PLUGIN_VERSION_OUTPUT | k8s-kms-plugin.version.output |  | string | false | Format of the version output. One of 'yaml' or 'json'. Env var: K8S_KMS_PLUGIN_VERSION_OUTPUT |
| k8s-kms-plugin version | --pretty | -P | K8S_KMS_PLUGIN_VERSION_PRETTY | k8s-kms-plugin.version.pretty | true | bool | false | Activate pretty print output for JSON. Env var: K8S_KMS_PLUGIN_VERSION_PRETTY |
| Command | Flags (long) | Flags (short) | Env Var | Config File Keys | Default Value | Type | Persistent Flag | Usage |