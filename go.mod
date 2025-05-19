module github.com/ThalesGroup/k8s-kms-plugin

go 1.23.9

require (
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0
	github.com/grpc-ecosystem/grpc-gateway v1.16.0
	github.com/infobloxopen/atlas-app-toolkit v1.4.0
	github.com/keepeye/logrus-filename v0.0.0-20190711075016-ce01a4391dd1
	github.com/miekg/pkcs11 v1.1.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/protoc-gen-go-json v1.1.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v1.10.0
	golang.org/x/sync v0.14.0
	golang.org/x/tools v0.33.0 // indirect
	google.golang.org/grpc v1.72.1
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.2.5 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.8.0 // indirect
	github.com/spf13/pflag v1.0.6
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	golang.org/x/tools/cmd/cover v0.1.0-deprecated
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/ThalesGroup/crypto11 v1.4.1
	github.com/ThalesGroup/gose v0.10.0
	github.com/hashicorp/go-version v1.7.0
	k8s.io/kms v0.32.2
)

require (
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
)

// TODO: remove this replace statement once the update to go1.23.9 is completed on the crypto11 repo
replace github.com/ThalesGroup/crypto11 v1.4.1 => github.com/ThalesGroup/crypto11 v1.4.1-0.20250515132444-7d70ab3e000b

// TODO: remove this replace statement once the update to go1.23.9 is completed on the gose repo
replace github.com/ThalesGroup/gose v0.10.0 => github.com/ThalesGroup/gose v0.10.1-0.20250515133433-21c55fca0ee1

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.6 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/jedib0t/go-pretty/v6 v6.6.7
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.9.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250512202823-5a2f75b736a9 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250512202823-5a2f75b736a9 // indirect
)
