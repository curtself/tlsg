#!/usr/bin/env bash
set -euo pipefail

VERSION="$(cat VERSION)"
COMMIT="$(git rev-parse --short HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

OS="${1:-$(go env GOOS)}"
ARCH="${2:-$(go env GOARCH)}"

mkdir -p dist

go fmt ./...
go vet ./...
#go test ./...

OUTPUT="dist/tlsg-${OS}-${ARCH}"
if [[ "${OS}" == "windows" ]]; then 
  OUTPUT+=".exe" 
fi

CGO_ENABLED=0 GOOS="${OS}" GOARCH="${ARCH}" go build -trimpath -ldflags="-s -w -X 'tlsg/internal/version.Version=${VERSION}' -X 'tlsg/internal/version.Commit=${COMMIT}' -X 'tlsg/internal/version.BuildDate=${BUILD_DATE}'" -o "${OUTPUT}"

