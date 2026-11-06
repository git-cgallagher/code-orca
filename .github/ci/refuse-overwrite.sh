#!/usr/bin/env bash
# Refuses to re-point an existing release tag (.github/workflows/image.yml, release job, tag runs only):
#   .github/ci/refuse-overwrite.sh <image> <X.Y.Z> <dir holding one empty file per platform digest>
# GHCR tags are mutable and consumers pin :X.Y.Z, so it must never move. Outcomes:
#   - the tag does not exist (the registry says "not found"):   ok, rerun=false
#   - it exists and its index lists exactly the digests in <dir>:   ok, rerun=true. This is a re-run of a release
#     job that already published the tags and then failed (an attestation, say); the job re-points the tags at the
#     EXISTING index (a carbon copy, same digest) and attests it.
#   - it exists with any other content:   fail (release a new version instead)
#   - the registry answers anything else (5xx, rate limit, auth):   fail. Never treated as "absent".
# Writes rerun=true|false to $GITHUB_OUTPUT (stdout without it).
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }

image=${1:?usage: refuse-overwrite.sh <image> <X.Y.Z> <digest dir>}
version=${2:?}
digests=${3:?}
tag=$image:$version
out=${GITHUB_OUTPUT:-/dev/stdout}

want=$(cd "$digests" && for d in *; do [ -f "$d" ] && echo "sha256:$d"; done | sort)
[ -n "$want" ] || fail "no digests in $digests"

err=$(mktemp)
trap 'rm -f "$err"' EXIT
if raw=$(docker buildx imagetools inspect --raw "$tag" 2> "$err"); then
  have=$(python3 -c 'import json, sys; print("\n".join(sorted(m["digest"] for m in json.load(sys.stdin).get("manifests", []))))' <<< "$raw") ||
    fail "$tag exists but is not an image index; release a new version instead"
  if [ "$have" = "$want" ]; then
    echo "::notice::$tag already exists with exactly these digests: a re-run; re-pointing the tags at the existing index"
    echo "rerun=true" >> "$out"
    exit 0
  fi
  fail "$tag already exists; release a new version instead"
fi
msg=$(cat "$err")
case $msg in
  *": not found"*|*MANIFEST_UNKNOWN*|*"manifest unknown"*)
    echo "rerun=false" >> "$out"
    exit 0 ;;
esac
fail "could not check whether $tag exists (registry error, not 'not found'): $msg"
