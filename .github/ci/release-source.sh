#!/usr/bin/env bash
# Finds the image a release promotes (.github/workflows/image.yml, release job):
#   .github/ci/release-source.sh <image> <commit sha> <empty digest dir>
# main's push run tagged <image>:sha-<short> (7 characters) when it built and tested <commit>. This checks that the
# tag is an index of exactly linux/amd64 + linux/arm64, that both images' org.opencontainers.image.revision label is
# the full <commit> (a short-SHA collision or a stale tag fails here), then writes one empty file per platform digest
# into <dir>, the layout refuse-overwrite.sh reads. The tag is resolved to its index digest ONCE and both reads use
# that digest, so the labels checked and the digests promoted come from the same index even if the tag moves.
# Writes amd64=<image>@<digest> to $GITHUB_OUTPUT (stdout without it), for the release-time vulnerability scan.
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }

image=${1:?usage: release-source.sh <image> <commit sha> <digest dir>}
commit=${2:?}
dir=${3:?}
src=$image:sha-${commit::7}

index=$(docker buildx imagetools inspect "$src" --format '{{json .Manifest.Digest}}' | tr -d '"') ||
  fail "$src is missing: main's image run did not publish $commit (tag a main commit whose image run passed)"
case $index in sha256:*) ;; *) fail "could not resolve $src to a digest (got '$index')" ;; esac
raw=$(docker buildx imagetools inspect --raw "$image@$index") || fail "could not read $image@$index"
labels=$(docker buildx imagetools inspect "$image@$index" --format '{{json .Image}}') ||
  fail "could not read the image config of $image@$index"

amd64=$(python3 - "$commit" "$dir" "$raw" "$labels" <<'PY'
import json, pathlib, sys
commit, out, raw, labels = sys.argv[1], pathlib.Path(sys.argv[2]), json.loads(sys.argv[3]), json.loads(sys.argv[4])
def fail(msg):
    print(f"::error::{msg}", file=sys.stderr); sys.exit(1)
plats = {f'{m["platform"]["os"]}/{m["platform"]["architecture"]}': m["digest"] for m in raw.get("manifests", [])}
if sorted(plats) != ["linux/amd64", "linux/arm64"] or len(raw["manifests"]) != 2:
    fail(f"the source index is not exactly linux/amd64 + linux/arm64: {sorted(plats)}")
for plat in plats:
    rev = ((labels.get(plat) or {}).get("config") or {}).get("Labels", {}).get("org.opencontainers.image.revision")
    if rev != commit:
        fail(f"the {plat} image's revision label is {rev!r}, not {commit}")
for digest in plats.values():
    (out / digest.removeprefix("sha256:")).touch()
print(plats["linux/amd64"])
PY
) || exit 1
echo "promoting $src = $image@$index ($commit)" >&2
echo "amd64=$image@$amd64" >> "${GITHUB_OUTPUT:-/dev/stdout}"
