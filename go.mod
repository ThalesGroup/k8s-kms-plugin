module github.com/ThalesGroup/k8s-kms-plugin

go 1.26.1

require (
	github.com/eclipse-keypont/pkcs11-go v0.0.0
	github.com/google/uuid v1.6.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/sync v0.20.0
	golang.org/x/tools v0.43.0 // indirect
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/tools/cmd/cover v0.1.0-deprecated
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/ThalesGroup/crypto11 v1.7.0-rc1
	github.com/ThalesGroup/gose v0.13.0-rc1
	github.com/creack/pty v1.1.24
	github.com/hashicorp/go-version v1.8.0
	github.com/lmittmann/tint v1.1.3
	golang.org/x/term v0.44.0
	k8s.io/kms v0.35.3
)

replace (
	github.com/ThalesGroup/crypto11 v1.7.0-rc1 => ../crypto11.github.com.ThalesGroup
	github.com/ThalesGroup/gose v0.13.0-rc1 => ../gose.github.com.ThalesGroup
	github.com/eclipse-keypont/pkcs11-go v0.0.0 => ../pkcs11-go
)

require (
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/mattn/go-runewidth v0.0.21 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/jedib0t/go-pretty/v6 v6.7.8
	github.com/pelletier/go-toml/v2 v2.3.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260319201613-d00831a3d3e7 // indirect
)
