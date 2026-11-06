#!/usr/bin/env bash
# Release check (.github/workflows/image.yml, release job): the tagged commit's own push runs on main passed.
#   .github/ci/main-runs-green.sh <commit sha>
# Needs GH_TOKEN (actions: read) and GITHUB_REPOSITORY. A release promotes the :sha-<short> image main's `image`
# run built and tested, so that run and main's `ci` run (pytest) must both have completed with success. The query is
# filtered to event=push on branch main: the tag run's own jobs share the commit SHA, so check-runs on the commit
# would count them too.
# Fails if either run is missing (not a main commit, or the run never started), still running, or not a success.
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }

sha=${1:?usage: main-runs-green.sh <commit sha>}
repo=${GITHUB_REPOSITORY:?}

runs=$(gh api "repos/$repo/actions/runs?head_sha=$sha&event=push&branch=main&per_page=100" \
  --jq '.workflow_runs[] | [.path, .status, (.conclusion // ""), (.id | tostring)] | @tsv') ||
  fail "could not list the workflow runs for $sha"

for wf in .github/workflows/ci.yml .github/workflows/image.yml; do
  # newest run first; a re-run updates the same run (run_attempt), so there is normally one per workflow
  line=$(awk -F'\t' -v wf="$wf" '$1 == wf' <<< "$runs" | sort -t$'\t' -k4,4nr | head -n1)
  [ -n "$line" ] || fail "no push run of $wf on main for $sha: tag a main commit whose $wf run passed"
  IFS=$'\t' read -r _ status conclusion id <<< "$line"
  [ "$status" = completed ] || fail "$wf on main for $sha is $status (run $id): wait for it, then re-run this job"
  [ "$conclusion" = success ] || fail "$wf on main for $sha concluded $conclusion (run $id): release a later green commit"
done
echo "main's ci and image runs passed for $sha"
