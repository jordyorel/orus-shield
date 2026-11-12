#!/bin/sh
# Installs the pinned Nuclei binary and nuclei-templates for the vulns module,
# after checking their SHA-256. Usage:
#
#   deploy/nuclei/install.sh [DIR]      # default DIR: .tools/nuclei (git-ignored)
#
# then set, in .env (absolute paths):
#
#   ORUS_NUCLEI_BIN=<DIR>/nuclei
#   ORUS_NUCLEI_TEMPLATES=<DIR>/nuclei-templates
#
# Updating: change the versions and hashes below together (take the binary
# hashes from the release's nuclei_<version>_checksums.txt), pick releases at
# least two weeks old, run the vulns integration test, and commit.
set -eu

NUCLEI_VERSION=3.11.1
TEMPLATES_VERSION=10.5.1
TEMPLATES_SHA256=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb

case "$(uname -s)_$(uname -m)" in
  Linux_x86_64)  platform=linux_amd64; sha=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6 ;;
  Linux_aarch64) platform=linux_arm64; sha=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07 ;;
  Darwin_arm64)  platform=macOS_arm64; sha=7d7e291addd1fc29a9bf8d089afe878a9799b20229cbea2fb1693fc40fd4c5f0 ;;
  Darwin_x86_64) platform=macOS_amd64; sha=75c47ce11e9dbd4288a1c895ed85e3c4df9f4acb8237d6d178da6dccd1628f2a ;;
  *) echo "unsupported platform: $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

dir=${1:-.tools/nuclei}
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

check() { # file expected-sha256
  got=$(shasum -a 256 "$1" 2>/dev/null || sha256sum "$1")
  got=${got%% *}
  if [ "$got" != "$2" ]; then
    echo "checksum mismatch for $1: got $got, want $2" >&2
    exit 1
  fi
}

echo "nuclei $NUCLEI_VERSION ($platform)"
curl -fsSL -o "$tmp/nuclei.zip" \
  "https://github.com/projectdiscovery/nuclei/releases/download/v$NUCLEI_VERSION/nuclei_${NUCLEI_VERSION}_${platform}.zip"
check "$tmp/nuclei.zip" "$sha"
unzip -q -o "$tmp/nuclei.zip" nuclei -d "$tmp"
install -m 0755 "$tmp/nuclei" "$dir/nuclei"

echo "nuclei-templates $TEMPLATES_VERSION"
curl -fsSL -o "$tmp/templates.tgz" \
  "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v$TEMPLATES_VERSION.tar.gz"
check "$tmp/templates.tgz" "$TEMPLATES_SHA256"
[ -d "$dir/nuclei-templates" ] && chmod -R u+w "$dir/nuclei-templates"
rm -rf "$dir/nuclei-templates"
mkdir "$dir/nuclei-templates"
tar xzf "$tmp/templates.tgz" -C "$dir/nuclei-templates" --strip-components=1
# The worker only reads templates: make that explicit.
chmod -R a-w "$dir/nuclei-templates"

echo
echo "ORUS_NUCLEI_BIN=$dir/nuclei"
echo "ORUS_NUCLEI_TEMPLATES=$dir/nuclei-templates"
