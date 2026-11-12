#!/bin/sh
# Builds orus-agent for Linux (amd64, arm64) and Windows (amd64), with the
# SHA-256 of each binary: until the agent is signed (a code signing
# certificate in the company's name), customers check the binary they
# download against SHA256SUMS published next to it.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
out="$root/dist/agent"
version="${1:-$(git -C "$root" describe --tags --always 2>/dev/null || echo dev)}"
mkdir -p "$out"
cd "$root/engine"
for target in linux/amd64 linux/arm64 windows/amd64; do
    os=${target%/*}
    arch=${target#*/}
    name="orus-agent-$version-$os-$arch"
    [ "$os" = windows ] && name="$name.exe"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out/$name" ./cmd/agent
done
cd "$out"
shasum -a 256 orus-agent-"$version"-* > SHA256SUMS
cat SHA256SUMS
