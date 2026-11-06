#!/usr/bin/env bash
# Prints, space-separated, which of the given X.Y.Z versions count as earlier releases for :latest and :X.Y.
#   .github/ci/counted-releases.sh <image> X.Y.Z...
# Needs GH_TOKEN (actions: read) and GITHUB_REPOSITORY. release-check.sh reads the result (RELEASED_VERSIONS).
# A version counts unless BOTH: <image>:X.Y.Z is absent from the registry AND the newest image.yml run for the tag
# vX.Y.Z completed without success. So a stray tag whose run failed (the "release tags: locked" ruleset keeps it)
# never freezes :latest, while a tag whose run is still going (two tags pushed together) or has no run at all still
# counts: the safe direction, at worst :latest/:X.Y stay where they are. Only a registry "not found" counts as
# absent; any other registry or API error fails, as in refuse-overwrite.sh.
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }

image=${1:?usage: counted-releases.sh <image> X.Y.Z...}
shift
repo=${GITHUB_REPOSITORY:?}

err=$(mktemp)
trap 'rm -f "$err"' EXIT
counted=()
for v in "$@"; do
  if docker buildx imagetools inspect --raw "$image:$v" > /dev/null 2> "$err"; then
    counted+=("$v")
    continue
  fi
  msg=$(cat "$err")
  case $msg in
    *": not found"*|*MANIFEST_UNKNOWN*|*"manifest unknown"*) ;;
    *) fail "could not check whether $image:$v exists (registry error, not 'not found'): $msg" ;;
  esac
  newest=$(gh api "repos/$repo/actions/workflows/image.yml/runs?event=push&branch=v$v&per_page=100" \
    --jq '.workflow_runs | sort_by(.id) | last | if . == null then "" else ([.status, (.conclusion // "none")] | @tsv) end') ||
    fail "could not list the image.yml runs for v$v"
  # dropped only when its newest run completed without success; no run, queued or in progress: counts
  if [[ $newest == completed$'\t'* && $newest != completed$'\t'success ]]; then
    continue
  fi
  counted+=("$v")
done
echo "${counted[*]:-}"
