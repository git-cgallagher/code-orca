# syntax=docker/dockerfile:1
# code-orca runtime image: ghcr.io/git-cgallagher/code-orca-runtime.
# Layered on ghcr.io/git-cgallagher/ansible-runtime (Python, ansible-core, boto3, collections, tini), not a fork
# of it, plus Terraform, PowerShell + PSScriptAnalyzer and the code-orca package. Build from the repo root:
#   docker buildx build -f container/Dockerfile --target runtime .
# Smoke test (from a checkout): docker run --rm -v "$PWD":/work -w /work <image> bash container/tests/smoke.sh
# Every version below is a build arg with a pinned default; container/tests/smoke.sh reads these defaults and
# fails when the image disagrees with them. Keep each ARG line free of trailing comments (the value would
# include them).

# BASE_IMAGE names the stage below by default, so the pinned base sits on a LITERAL `FROM image:tag@digest` line:
# Dependabot's docker updater reads only literal FROM lines (never `FROM ${ARG}`), so it can bump this one. A local
# override still works: --build-arg BASE_IMAGE=<image ref>.
ARG BASE_IMAGE=pinned-base

# The base's multi-arch INDEX digest (linux/amd64 + linux/arm64), ansible-runtime 1.3.0: Debian 13 trixie,
# Python 3.13, ansible-core 2.21.5. Bumping it can move any Python pin: rerun container/requirements/lock.sh.
FROM ghcr.io/git-cgallagher/ansible-runtime:1.3.0@sha256:81a0a154784d4d72efedb2b1070c8ebf31aab28a85862ab48480e8554c6aec05 AS pinned-base

FROM ${BASE_IMAGE} AS base

# ---------------------------------------------------------------------------------------------------------------
# Download stages: curl, gnupg and unzip live only here; the final stage copies or bind-mounts their results.
FROM base AS downloader
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl gnupg unzip \
 && rm -rf /var/lib/apt/lists/*

# Terraform from the GPG-verified release zip, NOT the hashicorp/terraform image: that image ships only the
# binary and no LICENSE.txt, and BSL 1.1 wants the license to travel with the binary. The key is fetched, but
# the signature must be a VALIDSIG whose PRIMARY key fingerprint is HashiCorp's (the last field of the status
# line), so a swapped key file cannot verify anything.
FROM downloader AS terraform
ARG TF_VERSION=1.14.7
ARG TARGETARCH
RUN set -eu; \
    test -n "${TARGETARCH}" || { echo "TARGETARCH is empty: build with buildx/BuildKit" >&2; exit 1; }; \
    fpr=C874011F0AB405110D02105534365D9472D7468F; \
    base_url="https://releases.hashicorp.com/terraform/${TF_VERSION}"; \
    zip="terraform_${TF_VERSION}_linux_${TARGETARCH}.zip"; \
    export GNUPGHOME="$(mktemp -d)"; work="$(mktemp -d)"; cd "$work"; \
    curl -fsSL --retry 3 -o hashicorp.asc https://www.hashicorp.com/.well-known/pgp-key.txt; \
    curl -fsSL --retry 3 -o "$zip" "$base_url/$zip"; \
    curl -fsSL --retry 3 -o SHA256SUMS "$base_url/terraform_${TF_VERSION}_SHA256SUMS"; \
    curl -fsSL --retry 3 -o SHA256SUMS.sig "$base_url/terraform_${TF_VERSION}_SHA256SUMS.sig"; \
    gpg --batch --quiet --import hashicorp.asc; \
    gpg --batch --with-colons --fingerprint | grep -q "^fpr:::::::::${fpr}:\$"; \
    gpg --batch --status-fd 1 --verify SHA256SUMS.sig SHA256SUMS > verify.status; \
    grep -Eq "^\[GNUPG:\] VALIDSIG .* ${fpr}\$" verify.status; \
    grep -E "^[0-9a-f]{64}  ${zip}\$" SHA256SUMS > one.sum; \
    test "$(wc -l < one.sum)" -eq 1; \
    sha256sum -c one.sum; \
    unzip -q "$zip" -d tf; \
    install -D -m 0755 tf/terraform /out/usr/local/bin/terraform; \
    install -D -m 0644 tf/LICENSE.txt /out/usr/share/licenses/terraform/LICENSE.txt; \
    cd /; rm -rf "$work" "$GNUPGHOME"

# Microsoft's repo definition for this Debian release. Trixie's apt (sqv) rejects the legacy microsoft.asc key;
# packages-microsoft-prod.deb carries the current keyring + sources entry. Its trust root is the HTTPS download.
FROM downloader AS msrepo
RUN set -eu; . /etc/os-release; mkdir -p /out; \
    curl -fsSL --retry 3 -o /out/packages-microsoft-prod.deb \
      "https://packages.microsoft.com/config/debian/${VERSION_ID}/packages-microsoft-prod.deb"; \
    dpkg-deb --info /out/packages-microsoft-prod.deb > /dev/null

# ---------------------------------------------------------------------------------------------------------------
# The code-orca wheel. The build backend (setuptools) is hash-pinned in container/requirements/build.txt and the
# wheel is built without build isolation, so nothing unhashed is fetched; this stage never ships.
FROM base AS builder
WORKDIR /src
COPY container/requirements/build.txt /tmp/build.txt
RUN pip install --root-user-action=ignore --require-hashes --no-deps -r /tmp/build.txt
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-build-isolation --no-deps -w /wheels . && ls /wheels/code_orca-*-py3-none-any.whl

# ---------------------------------------------------------------------------------------------------------------
FROM base AS runtime
ARG PWSH_VERSION=7.6.9
ARG PSSA_VERSION=1.25.0

# Terraform and PowerShell for unattended runs: no prompts, no checkpoint or telemetry calls (set before the
# build's own pwsh runs, too). The plugin cache is where bin/codeorca mounts the host's cache.
ENV TF_IN_AUTOMATION=1 \
    TF_INPUT=0 \
    TF_PLUGIN_CACHE_DIR=/root/.terraform.d/plugin-cache \
    CHECKPOINT_DISABLE=1 \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    POWERSHELL_UPDATECHECK=Off
RUN mkdir -p /root/.terraform.d/plugin-cache

# Terraform + its license (nothing else from the download stage: no gnupg, unzip or curl ships).
COPY --from=terraform /out/ /

# PowerShell 7.6 LTS from Microsoft's apt repo (both arches; 7.4 and 7.5 are end of life). The repo .deb is
# bind-mounted, so it never lands in a layer; apt lists are removed in the same RUN.
RUN --mount=type=bind,from=msrepo,source=/out,target=/mnt/msrepo \
    dpkg -i /mnt/msrepo/packages-microsoft-prod.deb \
 && apt-get update \
 && apt-get install -y --no-install-recommends "powershell=${PWSH_VERSION}-1.deb" \
 && rm -rf /var/lib/apt/lists/*
# PSScriptAnalyzer for `codeorca lint powershell` (AllUsers scope: visible whatever HOME a job sets). Smoke-test it
# with Invoke-ScriptAnalyzer: Get-InstalledPSResource reports nothing after a good install.
RUN pwsh -NoProfile -NonInteractive -Command "\$ErrorActionPreference = 'Stop'; \$ProgressPreference = 'SilentlyContinue'; Install-PSResource -Name PSScriptAnalyzer -Version '${PSSA_VERSION}' -Repository PSGallery -TrustRepository -Scope AllUsers" \
 && rm -rf /root/.cache/powershell /root/.local/share/powershell /tmp/*

# code-orca itself, into the base's own site-packages: deliberately NO separate venv. The shared dependency
# model (ansible-runtime docs/SHARED-DEPENDENCIES.md) is one version per package across the image, and the
# base's /usr/share/ansible-runtime/constraints.txt is the source of truth for every version it pins. So:
#   1. container/requirements/codeorca.txt holds only what the base LACKS, hash-pinned, installed under the
#      base's constraints (-c), so nothing the base pins can be upgraded or downgraded (today it is empty: the
#      base already pins jinja2, pydantic, ruamel.yaml, ansible-core and boto3, so this is a no-op);
#   2. the wheel goes in with --no-deps (a local wheel cannot be hash-checked; it was built from this context);
#   3. pip check proves the result is consistent: a base bump that drops or moves a dependency fails the build.
RUN --mount=type=bind,source=container/requirements,target=/mnt/req \
    --mount=type=bind,from=builder,source=/wheels,target=/mnt/wheels \
    pip install --root-user-action=ignore --require-hashes --no-deps \
      -c /usr/share/ansible-runtime/constraints.txt -r /mnt/req/codeorca.txt \
 && pip install --root-user-action=ignore --no-deps -c /usr/share/ansible-runtime/constraints.txt \
      /mnt/wheels/code_orca-*-py3-none-any.whl \
 && pip check \
 && codeorca --version

# Root, deliberately, as in ansible-runtime: the forwarded SSH-agent socket is root:root 0660, the Docker socket
# needs it, and GitHub `container:` jobs expect it. The container is single-use (`docker run --rm`).
WORKDIR /work
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["codeorca", "--help"]

# The labels' version and revision come from image.yml's build-args (a release tag labels X.Y.Z). They are declared
# HERE, after the last RUN: BuildKit hands every ARG in scope to each later RUN, so declared earlier a new value would
# rebuild the PowerShell and pip layers. The licenses name the main components: code-orca and PowerShell (MIT),
# Terraform (BUSL-1.1, its LICENSE.txt in /usr/share/licenses/terraform), ansible-core and ansible-lint
# (GPL-3.0-or-later). The base's collections and Debian packages carry their own; the SBOM attestation lists each.
ARG IMAGE_VERSION=dev
ARG IMAGE_REVISION=unknown
LABEL org.opencontainers.image.title="code-orca-runtime" \
      org.opencontainers.image.description="code-orca (Terraform + Ansible orchestrator) with pinned Terraform, ansible-core, PowerShell and PSScriptAnalyzer" \
      org.opencontainers.image.source="https://github.com/git-cgallagher/code-orca" \
      org.opencontainers.image.licenses="MIT AND BUSL-1.1 AND GPL-3.0-or-later" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${IMAGE_REVISION}"
