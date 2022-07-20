#!/bin/bash

grt() {
    cd "$(git rev-parse --show-toplevel || echo ".")"
}

version_dirty() {
  git diff --quiet || echo '-dirty'
}

version() {
  git describe --long --tags | sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g'
}

_goldflags="-X 'main.MWGPVersion=$(version)$(version_dirty)'"

grt

go build \
    -o mwgp \
    -ldflags "$_goldflags" \
    ./cmd/mwgp

