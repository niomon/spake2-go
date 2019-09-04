#!/bin/sh

set -e

BASEDIR=$( cd "$(dirname "$0")"/.. ; pwd -P )
cd "$BASEDIR"

go test ./... -p 2
