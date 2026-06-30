module github.com/ThalesGroup/k8s-kms-plugin

go 1.26.1

require (
	github.com/eclipse-keypont/pkcs11-go v0.0.0
	github.com/google/uuid v1.6.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.10.1
	github.com/stretchr/testify v1.11.1
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/spf13/afero v1.6.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.33.0 // indirect
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
	k8s.io/kms v0.36.2
)

replace (
	github.com/ThalesGroup/crypto11 v1.7.0-rc1 => ../crypto11.github.com.ThalesGroup
	github.com/ThalesGroup/gose v0.13.0-rc1 => ../gose.github.com.ThalesGroup
	github.com/eclipse-keypont/pkcs11-go v0.0.0 => ../pkcs11-go
)

require (
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mattn/go-runewidth v0.0.21 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/ini.v1 v1.66.2 // indirect
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/jedib0t/go-pretty/v6 v6.6.4
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260319201613-d00831a3d3e7 // indirect
)
