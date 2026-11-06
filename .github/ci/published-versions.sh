#!/usr/bin/env bash
# Prints, space-separated, which of the given X.Y.Z versions exist as <image>:X.Y.Z on the registry.
#   .github/ci/published-versions.sh <image> X.Y.Z...
# release-check.sh reads the result (RELEASED_VERSIONS) to decide :latest and :X.Y, so a v* tag whose run failed (a
# stray tag the "release tags: locked" ruleset keeps) never counts as a release. Only a registry "not found" counts
# as absent; any other error fails, as in refuse-overwrite.sh.
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }

image=${1:?usage: published-versions.sh <image> X.Y.Z...}
shift

err=$(mktemp)
trap 'rm -f "$err"' EXIT
found=()
for v in "$@"; do
  if docker buildx imagetools inspect --raw "$image:$v" > /dev/null 2> "$err"; then
    found+=("$v")
    continue
  fi
  msg=$(cat "$err")
  case $msg in
    *": not found"*|*MANIFEST_UNKNOWN*|*"manifest unknown"*) ;;
    *) fail "could not check whether $image:$v exists (registry error, not 'not found'): $msg" ;;
  esac
done
echo "${found[*]:-}"
