#!/bin/sh

set -e

BASEDIR=$( cd "$(dirname "$0")"/.. ; pwd -P )
cd "$BASEDIR"

go get "golang.org/x/lint/golint"
$GOPATH/bin/golint -set_exit_status ./...