#!/usr/bin/env bash
set -euo pipefail

VERSION="$(cat VERSION)"
COMMIT="$(git rev-parse --short HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p dist

go fmt ./...
go vet ./...
#go test ./...

#CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}' -X 'main.BuildDate=${BUILD_DATE}'" -o "dist/ssl-tools"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X 'ssl-tools/internal/version.Version=${VERSION}' -X 'ssl-tools/internal/version.Commit=${COMMIT}' -X 'ssl-tools/internal/version.BuildDate=${BUILD_DATE}'" -o "dist/ssl-tools"
