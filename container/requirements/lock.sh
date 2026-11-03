#!/usr/bin/env bash
# Regenerates container/requirements/{codeorca,build}.txt from the .in files, INSIDE the base image the
# Dockerfile pins (BASE_IMAGE's default), so the lock resolves for that Python (3.13, Linux) and against the
# base's own pins: --constraint=/usr/share/ansible-runtime/constraints.txt means a package the base already
# installs can only resolve to the base's version. Run it from anywhere; it needs Docker and network (PyPI).
#   container/requirements/lock.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
base=$(sed -n 's/^ARG BASE_IMAGE=\(.*\)$/\1/p' "$root/container/Dockerfile")
[ -n "$base" ] || { echo "no ARG BASE_IMAGE= default in container/Dockerfile" >&2; exit 1; }
docker run --rm -v "$root":/src -w /src "$base" sh -euc '
  pip install --quiet --root-user-action=ignore --timeout 60 --retries 5 pip-tools
  for name in codeorca build; do
    pip-compile --quiet --generate-hashes --allow-unsafe --strip-extras \
      --constraint=/usr/share/ansible-runtime/constraints.txt \
      --output-file=container/requirements/$name.txt container/requirements/$name.in
  done'
