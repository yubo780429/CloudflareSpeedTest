#!/usr/bin/env bash
set -Eeuo pipefail
export CGO_ENABLED=0
export GOOS=linux
export GOARCH="${GOARCH:-amd64}"

version="$(go version)"
if [[ ! "$version" =~ go1\.([0-9]+) ]]; then
  echo "Unable to parse Go version: $version" >&2
  exit 1
fi
if (( BASH_REMATCH[1] < 26 )); then
  echo "quic-go v0.66.0 requires Go 1.26 or newer. Current: $version" >&2
  exit 1
fi

echo "Using $version"
go mod tidy
go build -trimpath -ldflags='-s -w' -o "cfst-dualbench-linux-${GOARCH}" .
echo "Build completed: $PWD/cfst-dualbench-linux-${GOARCH}"
