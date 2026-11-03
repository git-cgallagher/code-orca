# The code-orca-runtime container image

`ghcr.io/git-cgallagher/code-orca-runtime:<version>` is the execution environment code-orca is meant to run in:
one image holding the orchestrator plus every tool its steps call, at exact versions, for `linux/amd64` and
`linux/arm64`. `codeorca doctor` checks a running environment against a project's `runtime:` block and fails
closed on any mismatch.

## What is in it, and why

| Layer | Source | Why |
|---|---|---|
| Base | `ghcr.io/git-cgallagher/ansible-runtime` (the Dockerfile's `BASE_IMAGE` default, pinned by tag **and** multi-arch index digest) | Debian 13 trixie, Python 3.13, ansible-core and the shared collections. Layered on, not forked, so the estate has one source of truth for Ansible and Python pins (`/usr/share/ansible-runtime/constraints.txt`). Runs as root deliberately, as the base does: the forwarded ssh-agent socket and the Docker socket need it. Entrypoint is the base's `tini`. |
| Terraform | the HashiCorp release zip (`TF_VERSION`), GPG-verified against HashiCorp's key (fingerprint `C874 011F 0AB4 0511 0D02 1055 3436 5D94 72D7 468F`) and its `SHA256SUMS` | Not the `hashicorp/terraform` image: it ships no `LICENSE.txt`, and BSL 1.1 wants the license to travel with the binary. The license is installed at `/usr/share/licenses/terraform/LICENSE.txt`, and the image is labelled `org.opencontainers.image.licenses="MIT AND BUSL-1.1"`. |
| PowerShell | Microsoft's apt repo for Debian 13 (`packages-microsoft-prod.deb`), `powershell=<PWSH_VERSION>-1.deb`, on both arches | The `powershell` helper step and `codeorca lint powershell`. Pinned to the 7.6 LTS line (7.4 and 7.5 are end of life). Trixie's apt rejects Microsoft's legacy `microsoft.asc` key, so the repo comes from the `.deb`. |
| PSScriptAnalyzer | PowerShell Gallery, `PSSA_VERSION`, `Install-PSResource -Scope AllUsers` | `codeorca lint powershell`. The smoke test proves it with `Invoke-ScriptAnalyzer` (`Get-InstalledPSResource` reports nothing even after a good install). |
| code-orca | this repository, installed under the base's constraints | So the orchestrator can never upgrade a package ansible-core or the collections rely on. |

The exact pins live in `container/Dockerfile` (ARG defaults) and `container/requirements/`; this page does not
repeat them, so it cannot go stale. `docker inspect` on an image shows its labels; `codeorca doctor --lock`
prints the versions it observes.

## Build and smoke-test locally

From the repository root (the whole checkout is the build context, filtered by `.dockerignore`):

```bash
docker buildx build -f container/Dockerfile --target runtime --load -t code-orca-phase4-local:test .
docker run --rm -v "$PWD":/work -w /work code-orca-phase4-local:test bash container/tests/smoke.sh
git status --porcelain   # must print nothing: the smoke test leaves the checkout clean
```

The smoke test needs no network beyond what the reference project needs (none) and exits 0 on success. The
build arguments `BASE_IMAGE`, `TF_VERSION`, `PWSH_VERSION` and `PSSA_VERSION` have defaults in the Dockerfile;
pass `--build-arg` only to try a bump.

- **Apple silicon builds `linux/arm64` natively; that is the only architecture to verify locally.** amd64
  emulation (binfmt) is broken on this Mac and is deliberately not being reinstalled; CI builds and tests amd64
  on a native runner.
- Docker Desktop on this Mac is shared with other workloads: never stop, restart or prune it. Remove only what
  you created (`docker rmi code-orca-phase4-local:test`).

## Run it: `bin/codeorca`

`bin/codeorca` is the local launch wrapper (its header comment is the authoritative list of what it mounts and
passes). It runs `codeorca "$@"` in the image with the current directory at `/work`:

```bash
aws-vault exec <profile> -- bin/codeorca run plan-only -p codeorca.yaml
CODEORCA_IMAGE=ghcr.io/git-cgallagher/code-orca-runtime:X.Y.Z bin/codeorca doctor
```

- **Credentials by name only.** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
  `AWS_CREDENTIAL_EXPIRATION`, `AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_PROFILE` (each only when set), every
  `CODEORCA_*` (the redaction key included) and every `TF_VAR_*` go on `docker run -e NAME`: Docker copies the
  value from the calling shell, so no value is on the argv (`ps`, shell history) and nothing is written to disk.
  Never `--env-file`. The values are still visible in `docker inspect` while the container lives (an accepted
  residual: short-lived STS, `--rm`, single-user machine).
- **The wrapper never runs aws-vault.** The caller wraps it, as above. aws-vault's `--ecs-server` cannot serve a
  container (SDKs refuse non-loopback credential URLs).
- **`AWS_PROFILE` caution:** no `~/.aws` is mounted, so a profile name passed into the container refers to a
  profile that does not exist there; unset it in the calling shell unless the image is meant to see it.
- **`-it` only when stdin and stdout are both terminals.** A human at a terminal can answer a gate or
  `codeorca resume --approve`; an agent or a pipe gets no TTY, so the gate stops the run at exit 3 and resume
  refuses. That is the approval invariant, not a limitation.
- **The Docker socket is mounted only with `CODEORCA_DOCKER_SOCKET=1`** (it is host-root-equivalent; only
  Molecule or `community.docker` need it).
- ssh agent (Docker Desktop's `/run/host-services/ssh-auth.sock` on macOS, `$SSH_AUTH_SOCK` on Linux),
  `~/.ssh/known_hosts` read-only, and `~/.terraform.d/plugin-cache` (created if absent) are mounted.
- **The image runs as root.** On Linux, files it writes under `$PWD` are root-owned; after the run the wrapper
  chowns the project's state dir (the first component of `state_dir`, normally `.codeorca`) and `specs_dir` back
  to the caller, nothing else (a symlinked dir, an absolute path or one with `..` is skipped). Terraform's own
  working files (`.terraform/`, `.terraform.lock.hcl`) and the plugin cache stay root-owned on Linux. On Docker
  Desktop for macOS files already show as the caller's. The wrapper's exit code is always codeorca's.
- The image defaults to `:latest`. Set `CODEORCA_IMAGE` to the same image as the project's `runtime.image` so
  `codeorca doctor` checks the image you meant.

## CI and releases (`.github/workflows/image.yml`)

| Trigger | Builds + smoke + scan | Pushes |
|---|---|---|
| pull request (every PR: no path filter, so the checks can be required) | amd64 + arm64 | nothing |
| push to `main` touching `container/**`, `src/**`, `pyproject.toml`, the workflow or `examples/reference/**` | amd64 + arm64 | `:main`, `:sha-<short>` |
| weekly schedule (Monday 07:00 UTC, on `main`) | amd64 + arm64 | `:main` only (Debian security updates; never a release tag) |
| manual run (`workflow_dispatch`) | amd64 + arm64 | `:main` on `main`; nothing on any other branch |
| tag `vX.Y.Z` | amd64 + arm64 | `:X.Y.Z`, `:X.Y`, `:latest` |

Each architecture builds on its own native runner (`image (amd64)` on `ubuntu-24.04`, `image (arm64)` on
`ubuntu-24.04-arm`), loads the image, runs the smoke test from the checkout, checks the checkout is still clean,
and scans with grype (amd64, failing on a fixable critical finding). Outside pull requests each pushes its image
by digest; the `manifest` job joins the two digests under the tags, then attaches build provenance
(`actions/attest-build-provenance`) and an SPDX SBOM (`anchore/sbom-action` + `actions/attest-sbom`) to the
multi-arch index, both pushed to the registry. `image (amd64)` and `image (arm64)` are meant to be required
checks on the "main protection" ruleset once they have run once.

**Releasing X.Y.Z:**

1. In a PR, set `version = "X.Y.Z"` in `pyproject.toml` (and the CHANGELOG), and point
   `examples/reference/codeorca.yaml`'s `runtime.image` at the new tag. Merge it.
2. Tag the merge commit `vX.Y.Z` and push the tag (a public release: Chris pushes it).
3. The workflow fails if the tag differs from `pyproject.toml`'s version, and refuses to re-point an existing
   `:X.Y.Z` (GHCR tags are mutable; consumers pin them). A broken release is fixed by releasing the next version.

`pyproject.toml` still says `0.0.1` while the reference project names `code-orca-runtime:0.1.0`, so the first
release needs the version bump in step 1.

## Pull and verify

```bash
docker pull ghcr.io/git-cgallagher/code-orca-runtime:X.Y.Z
digest=$(docker buildx imagetools inspect ghcr.io/git-cgallagher/code-orca-runtime:X.Y.Z --format '{{json .Manifest.Digest}}' | tr -d '"')
gh attestation verify "oci://ghcr.io/git-cgallagher/code-orca-runtime@$digest" --owner git-cgallagher
# the SBOM attestation (syft writes SPDX 2.3):
gh attestation verify "oci://ghcr.io/git-cgallagher/code-orca-runtime@$digest" --owner git-cgallagher \
  --predicate-type https://spdx.dev/Document/v2.3
```

Verify the index digest (what `imagetools inspect` prints), which is what the attestations name. The SBOM
describes the `linux/amd64` image (syft resolves the index to the runner's platform); both architectures are
built from the same pins. Pin consumers by tag and digest: `code-orca-runtime:X.Y.Z@sha256:...`.

## GHCR package visibility (one manual step, Chris)

GitHub's documentation says a newly published package starts **private**; for a personal account only the owner
can change that, in the UI: GitHub, Your profile, Packages, `code-orca-runtime`, Package settings, Danger Zone,
Change visibility, Public. After the first push from
`main`, check it anonymously (this leaves any GHCR login alone), and make it public if it prints anything but 200:

```bash
t=$(curl -fsS "https://ghcr.io/token?scope=repository:git-cgallagher/code-orca-runtime:pull" | python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])')
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $t" \
  -H 'Accept: application/vnd.oci.image.index.v1+json' https://ghcr.io/v2/git-cgallagher/code-orca-runtime/manifests/main
```

While it is private the pipeline itself still works (it logs in with `GITHUB_TOKEN`); anonymous pulls (consumers, `bin/codeorca` on a machine without a GHCR login) do not.

ansible-runtime's package is public today (an anonymous token and manifest fetch for `:1.3.0` succeeded on
2026-11-03), but its AGENTS.md, README and CHANGELOG do not record how or when it was made public, so whether
that took the same manual step is not documented there.

## Bumping a pin

All bumps go through a PR; the image workflow's two jobs prove the result on both architectures.

**The base.** The Dockerfile names the base on a literal, digest-pinned stage
(`FROM ghcr.io/git-cgallagher/ansible-runtime:X.Y.Z@sha256:<index digest> AS pinned-base`) and the `BASE_IMAGE`
argument defaults to that stage (`ARG BASE_IMAGE=pinned-base` before the first `FROM`, then
`FROM ${BASE_IMAGE} AS base`). Dependabot's docker updater reads only literal `FROM` lines, so the `docker` entry
in `.github/dependabot.yml` (directory `/container`) opens the bump PR for this line; a local build can still
override it with `--build-arg BASE_IMAGE=<ref>`. A base bump can move any Python pin and the reference project's
`runtime:` block (`ansible_core`, `python`): rerun `container/requirements/lock.sh` and the smoke test in the same
PR. To bump by hand: `docker buildx imagetools inspect ghcr.io/git-cgallagher/ansible-runtime:<ver>` prints the
index digest to paste into that `FROM` line.

**Terraform (`TF_VERSION`).** Change it together with `.github/workflows/ci.yml`'s `terraform_version`, the
reference project's `runtime.terraform`, and the captured fixtures (`tests/fixtures/terraform/regenerate.py`):
the tests and the image must agree. The Dockerfile re-verifies the new zip against HashiCorp's key and
`SHA256SUMS`; nothing else needs to change.

**PowerShell (`PWSH_VERSION`).** Stay on 7.6.x. The newest 7.6.x must exist for both architectures in Microsoft's
Debian 13 index:

```bash
for a in amd64 arm64; do
  curl -fsSL "https://packages.microsoft.com/debian/13/prod/dists/trixie/main/binary-$a/Packages" |
    awk '/^Package: /{p=$2} /^Version: /{if (p == "powershell") print $2}' | sort -V | tail -n1
done   # e.g. 7.6.9-1.deb for both (2026-11-03); PWSH_VERSION is the part before -1.deb
```

Update the reference project's `runtime.pwsh` only when the line changes (it is `7.6.*`).

**PSScriptAnalyzer (`PSSA_VERSION`).** The new version must be on the PowerShell Gallery; the smoke test's
`Invoke-ScriptAnalyzer` run proves the install.

**Actions in `image.yml`.** Dependabot's `github-actions` entry bumps the SHA and its `# vX.Y.Z` comment
together.
