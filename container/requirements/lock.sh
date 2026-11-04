#!/usr/bin/env bash
# Regenerates container/requirements/{codeorca,build}.txt from the .in files, INSIDE the base image the
# Dockerfile pins (the literal `FROM <image>@sha256:<digest> AS pinned-base` line), so the lock resolves for that
# Python (3.13, Linux) and against the base's own pins: --constraint=/usr/share/ansible-runtime/constraints.txt
# means a package the base already installs can only resolve to the base's version. Run it from anywhere; it needs
# Docker and network (PyPI).
#   container/requirements/lock.sh                 # lock against the pinned base
#   BASE_IMAGE=<image>@sha256:<digest> container/requirements/lock.sh   # try a bump before editing the Dockerfile
#   container/requirements/lock.sh --print-base    # print the image it would use, and exit
# `ARG BASE_IMAGE=` in the Dockerfile names the STAGE (`pinned-base`), not an image, so it is never read here.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
base=${BASE_IMAGE:-$(sed -n 's/^FROM \([^ ]*\) AS pinned-base$/\1/p' "$root/container/Dockerfile")}
[ -n "$base" ] || { echo "no 'FROM <image> AS pinned-base' line in container/Dockerfile" >&2; exit 1; }
case $base in
  */*@sha256:*) ;;
  *) echo "base image '$base' is not a digest-pinned image reference (<registry>/<name>[:tag]@sha256:<digest>)" >&2
     exit 1 ;;
esac
if [ "${1:-}" = --print-base ]; then echo "$base"; exit 0; fi
docker run --rm -v "$root":/src -w /src "$base" sh -euc '
  pip install --quiet --root-user-action=ignore --timeout 60 --retries 5 pip-tools
  for name in codeorca build; do
    pip-compile --quiet --generate-hashes --allow-unsafe --strip-extras \
      --constraint=/usr/share/ansible-runtime/constraints.txt \
      --output-file=container/requirements/$name.txt container/requirements/$name.in
  done'
