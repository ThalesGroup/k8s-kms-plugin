#!/usr/bin/env bash

# ENV
CURRENT_PATH="$(realpath "$0")"
CURRENT_DIR="$(dirname "${CURRENT_PATH}")"
PROJECT_DIR="$(dirname "${CURRENT_DIR}")"

# VARS
build_args=(go build)
dev_mode=false
debug_mode=false
branch_name=""

# FUNCTIONS
function help(){
    printf "[Overview]
build.sh --help
This script helps to build the k8s-kms-plugin, covering different development and debug options.

[Usage]
build.sh [opts:--dev|--debug]

[Arguments]

[Options]
--dev [branch_name]     Optional. If enabled, use the git branch name to pull the Crypto11 and Gose dependencies and build the k8s-kms-plugin with it.
--debug                 Optional. If enabled, use delve to build the k8s-kms-plugin for remote debug.

[Examples]
$ build.sh
  # build the k8s-kms-plugin

$ build.sh --dev
  # build the k8s-kms-plugin using the current git branch name to pull the crypto11 and gose dependencies
"
}

function init(){
    #echo "init vars and env here"
    if [ "${dev_mode}" = true ]; then
      if [ -z "${branch_name}" ]; then
        echo "ERROR: dev mode needs a branch name in arguments"
        help
        exit 1
      fi
      echo "Dev mode enabled"
      echo "Build using branch ${branch_name}"
      git switch "${branch_name}"
      eval GOPROXY=direct go get -u "github.com/ThalesGroup/crypto11@${branch_name}"
      eval GOPROXY=direct go get -u "github.com/ThalesGroup/gose@${branch_name}"
      go mod tidy
    fi

    if [ "${debug_mode}" = true ]; then
      echo "Debug mode enabled"
      # DO NOT REMOVE ANTI SLASH
      build_args+=(-gcflags=\"all=-N -l\")
      echo "${build_args[@]}"
    fi

    build_args+=(-o k8s-kms-plugin "${PROJECT_DIR}/cmd/k8s-kms-plugin/main.go")
}

# customize image
function start(){
#    build_cmd="go ${build_args[@]}"
    # build
    echo "build k8s-kms-plugin"
    eval "${build_args[@]}"

    echo "Done"
}

# PARSING
#if [ $# -eq 0 ]; then help; fi # if no arguments given to this script
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
    -h|--help|help)
        help
        exit 0
        ;;
    --dev)
        dev_mode=true
        branch_name="$2"
        shift 2
        ;;
    --debug)
        debug_mode=true
        shift
        ;;
    *) # unknown option
        format "$1"
        shift              # past argument
        ;;
    esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

# MAIN
init
start

exit 0