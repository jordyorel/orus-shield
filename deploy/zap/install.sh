#!/bin/sh
# Installs the pinned OWASP ZAP image used by the zap module (deep profile,
# "Approfondi") and prints the worker's variables.
#
# The image is pinned by digest: a tag can be moved to other content, a
# digest cannot. Docker checks the digest of what it downloads. To upgrade,
# pick a stable build at least two weeks old on
# https://hub.docker.com/r/zaproxy/zap-stable/tags, and update both lines.
#
# ZAP (Apache-2.0) runs in Docker; its only route out is the worker's
# gateproxy (see engine/internal/modules/zap). In production, also deny
# the container any other network access.
set -eu

TAG="20261026"
DIGEST="sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238"
IMAGE="zaproxy/zap-stable:${TAG}@${DIGEST}"

command -v docker >/dev/null 2>&1 || { echo "docker is missing" >&2; exit 1; }
docker pull "$IMAGE"

# The runs' files are mounted into the container: Colima (macOS) shares only
# the home directory, so keep them there.
WORKDIR="${HOME}/.cache/orus-zap"
mkdir -p "$WORKDIR"
chmod 700 "$WORKDIR"

echo
echo "Add to .env (worker only):"
echo "ORUS_ZAP_IMAGE=$IMAGE"
echo "ORUS_ZAP_WORKDIR=$WORKDIR"
echo "# Linux (Docker Engine): ORUS_ZAP_NETWORK=host and ORUS_ZAP_PROXY_HOST=127.0.0.1"
