module github.com/ThalesGroup/k8s-kms-plugin

go 1.21.6

// TODO replace packages :
//   - gose
//   - crypto11
require (
	github.com/golang/protobuf v1.5.3
	github.com/google/uuid v1.6.0
	github.com/grpc-ecosystem/grpc-gateway v1.15.2
	github.com/infobloxopen/atlas-app-toolkit v0.22.1
	github.com/keepeye/logrus-filename v0.0.0-20190711075016-ce01a4391dd1
	github.com/miekg/pkcs11 v1.1.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/protoc-gen-go-json v0.0.0-20200917194518-364b693410ae
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.8.4
	golang.org/x/sync v0.6.0
	golang.org/x/tools v0.17.0 // indirect
	google.golang.org/grpc v1.61.0
	google.golang.org/protobuf v1.31.0
	k8s.io/apiserver v0.19.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.1.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/pelletier/go-toml v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.0 // indirect
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools/cmd/cover v0.1.0-deprecated
	google.golang.org/genproto v0.0.0-20231106174013-bbf56f31fb17 // indirect
	gopkg.in/ini.v1 v1.51.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/ThalesGroup/crypto11 v1.2.6-0.20240209151343-55d45d454b19
	github.com/ThalesGroup/gose v0.8.8-0.20240212085359-57890b0e2357
)

require (
	google.golang.org/genproto/googleapis/api v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231106174013-bbf56f31fb17 // indirect
)
