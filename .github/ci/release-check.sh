#!/usr/bin/env bash
# Release checks for a `vX.Y.Z` tag run of .github/workflows/image.yml. Run from a FULL checkout (fetch-depth: 0,
# so origin/main and every tag are present):
#   .github/ci/release-check.sh vX.Y.Z
# Fails unless
#   - the tag is a strict vX.Y.Z (no prerelease or build suffix: metadata-action emits no version tag for one, so
#     the image would get only :latest and the overwrite refusal would check a tag that is never written),
#   - it equals pyproject.toml's version,
#   - the commit (GITHUB_SHA, else HEAD) is on origin/main (a tag on an unreviewed branch commit is not a release).
# Then writes to $GITHUB_OUTPUT (stdout without it):
#   version=X.Y.Z
#   latest=true|false   this is the highest vX.Y.Z on main: only then does it move :latest
#   minor=true|false    this is the highest vX.Y.* on main: only then does it move :X.Y
# so a backport (v0.1.5 after v0.2.0) or two tags racing never move :latest or :X.Y backwards.
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }

ref=${1:?usage: release-check.sh vX.Y.Z}
main=${RELEASE_MAIN_REF:-origin/main}
strict='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

printf '%s\n' "$ref" | grep -Eq "$strict" || fail "tag $ref is not a release tag vX.Y.Z (no prerelease or build suffix)"
version=${ref#v}

py=$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
[ "$py" = "$version" ] || fail "tag $ref does not match pyproject.toml version $py"

commit=${GITHUB_SHA:-$(git rev-parse HEAD)}
git rev-parse --verify --quiet "$main^{commit}" > /dev/null || fail "$main is not in this checkout (check out with fetch-depth: 0)"
git merge-base --is-ancestor "$commit" "$main" || fail "$ref ($commit) is not on $main: tag the merge commit on main"

# Released versions: strict vX.Y.Z tags on main, plus this one.
released=$( { git tag -l 'v*' --merged "$main"; echo "$ref"; } | grep -E "$strict" || true)
# shellcheck disable=SC2086  # $released is strict vX.Y.Z words only
verdict=$(python3 -c '
import sys
mine = tuple(map(int, sys.argv[1].split(".")))
tags = {tuple(map(int, t[1:].split("."))) for t in sys.argv[2:]}
same_line = [t for t in tags if t[:2] == mine[:2]]
print(str(mine == max(tags)).lower(), str(mine == max(same_line)).lower())
' "$version" $released)
latest=${verdict% *}
minor=${verdict#* }

out=${GITHUB_OUTPUT:-/dev/stdout}
printf 'version=%s\nlatest=%s\nminor=%s\n' "$version" "$latest" "$minor" >> "$out"
