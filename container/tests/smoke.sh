#!/usr/bin/env bash
# Runs INSIDE the code-orca runtime image and proves it holds exactly what container/Dockerfile pins, then runs
# the reference project end to end. From a checkout (the one the image was built from):
#   docker run --rm -v "$PWD":/work -w /work <image> bash container/tests/smoke.sh
# Exit 0 = pass. No network: the reference project needs none (local backend, provider-free stack,
# connection: local). It never writes into the checkout: every run works on a copy of examples/reference in a
# temp dir, so `git status --porcelain` in the checkout is unchanged afterwards. It never calls git (the bind
# mount's owner differs from root, so git would refuse the repo as "dubious ownership").
# Every check is its own fatal `if`: under `bash -e` a `! cmd` never fails the script.
set -euo pipefail

fail() { echo "::error::smoke: $*" >&2; exit 1; }
step() { echo "== $*"; }

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
dockerfile=$root/container/Dockerfile
[ -f "$dockerfile" ] || fail "no container/Dockerfile under $root: run this from a code-orca checkout"

# The pins are the Dockerfile's ARG defaults (build args are not visible at run time).
arg() { sed -n "s/^ARG $1=\(.*\)\$/\1/p" "$dockerfile" | head -n 1; }
tf_want=$(arg TF_VERSION)
pwsh_want=$(arg PWSH_VERSION)
pssa_want=$(arg PSSA_VERSION)
for v in tf_want pwsh_want pssa_want; do
  if [ -z "${!v}" ]; then fail "could not read $v from $dockerfile"; fi
done

step "contract: tini is PID 1, codeorca is on PATH, WORKDIR /work"
if [ "$(cat /proc/1/comm)" != tini ]; then fail "PID 1 is $(cat /proc/1/comm), want tini (the image ENTRYPOINT)"; fi
if ! command -v codeorca > /dev/null; then fail "codeorca is not on PATH"; fi
if [ "$(pwd)" != /work ]; then fail "cwd is $(pwd), want /work"; fi

step "terraform ${tf_want}"
tf_have=$(terraform version -json | python3 -c 'import json, sys; print(json.load(sys.stdin)["terraform_version"])')
if [ "$tf_have" != "$tf_want" ]; then fail "terraform is $tf_have, the Dockerfile pins $tf_want"; fi
if [ ! -s /usr/share/licenses/terraform/LICENSE.txt ]; then fail "/usr/share/licenses/terraform/LICENSE.txt is missing"; fi
if ! grep -q "Business Source License" /usr/share/licenses/terraform/LICENSE.txt; then
  fail "/usr/share/licenses/terraform/LICENSE.txt is not Terraform's BSL 1.1 license"
fi

step "pwsh ${pwsh_want}"
pwsh_have=$(pwsh -v)
if [ "$pwsh_have" != "PowerShell ${pwsh_want}" ]; then fail "pwsh -v is '$pwsh_have', the Dockerfile pins ${pwsh_want}"; fi

step "PSScriptAnalyzer ${pssa_want} runs"
# Get-InstalledPSResource reports nothing after a good install: load the module and lint a known finding.
pssa_have=$(pwsh -NoProfile -NonInteractive -Command \
  '$ErrorActionPreference = "Stop"; Import-Module PSScriptAnalyzer; (Get-Module PSScriptAnalyzer).Version.ToString()')
if [ "$pssa_have" != "$pssa_want" ]; then fail "PSScriptAnalyzer is $pssa_have, the Dockerfile pins $pssa_want"; fi
rules=$(pwsh -NoProfile -NonInteractive -Command \
  '$ErrorActionPreference = "Stop"; (Invoke-ScriptAnalyzer -ScriptDefinition "function f { Write-Host hi }").RuleName')
if ! grep -qx PSAvoidUsingWriteHost <<< "$rules"; then fail "Invoke-ScriptAnalyzer did not report PSAvoidUsingWriteHost (got: $rules)"; fi

step "ansible-core equals the base's pin"
core_want=$(sed -n 's/^ansible-core==\([^ ;]*\).*/\1/p' /usr/share/ansible-runtime/constraints.txt)
core_have=$(python3 -c 'from ansible.release import __version__; print(__version__)')
if [ -z "$core_want" ]; then fail "no ansible-core pin in /usr/share/ansible-runtime/constraints.txt"; fi
if [ "$core_have" != "$core_want" ]; then fail "ansible-core is $core_have, the base pins $core_want"; fi

step "code-orca: version, Python dependencies"
pkg_want=$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' "$root/pyproject.toml")
pkg_have=$(python3 -c 'import importlib.metadata as m; print(m.version("code-orca"))')
if [ "$pkg_have" != "$pkg_want" ]; then fail "installed code-orca is $pkg_have, this checkout's pyproject.toml says $pkg_want"; fi
cli_have=$(codeorca --version)
if [ "$cli_have" != "codeorca ${pkg_want}" ]; then fail "codeorca --version is '$cli_have', want 'codeorca ${pkg_want}'"; fi
if ! pip check; then fail "pip check found broken requirements"; fi
# Every base pin is what is installed, and code-orca's own pins (codeorca.txt) too: nothing moved a base package.
if ! python3 - "$root/container/requirements/codeorca.txt" <<'PY'
import re
import sys
from importlib.metadata import PackageNotFoundError, version

bad = []
for path in ("/usr/share/ansible-runtime/constraints.txt", sys.argv[1]):
    for line in open(path):
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", line)
        if not m:
            continue
        try:
            have = version(m[1])
        except PackageNotFoundError:
            have = None
        if have != m[2]:
            bad.append(f"{path}: {m[1]} pinned {m[2]}, installed {have}")
sys.exit("\n".join(bad) if bad else 0)
PY
then fail "an installed Python package differs from its pin"; fi
if ! python3 -c 'import ansible, boto3, botocore, jinja2, pydantic, ruamel.yaml'; then fail "a code-orca dependency does not import"; fi

step "build tools did not ship"
for tool in gpg unzip curl; do
  if command -v "$tool" > /dev/null; then fail "$tool is in the image (it belongs to the download stage only)"; fi
done

step "environment for unattended runs"
for kv in TF_IN_AUTOMATION=1 TF_INPUT=0 CHECKPOINT_DISABLE=1 POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off \
    TF_PLUGIN_CACHE_DIR=/root/.terraform.d/plugin-cache; do
  name=${kv%%=*}
  if [ "${!name:-}" != "${kv#*=}" ]; then fail "$name is '${!name:-}', want '${kv#*=}'"; fi
done
if [ ! -d "$TF_PLUGIN_CACHE_DIR" ]; then fail "TF_PLUGIN_CACHE_DIR $TF_PLUGIN_CACHE_DIR does not exist"; fi

# ------------------------------------------------------------------------------------------- reference project
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ref=$work/reference
cp -a "$root/examples/reference" "$ref"
# Local leftovers in the checkout (gitignored run state, specs, Terraform working files) must not seed the copy.
rm -rf "$ref/.codeorca" "$ref/specs"
find "$ref" \( -name '.terraform' -o -name '.terraform.lock.hcl' -o -name '*.tfstate' -o -name '*.tfstate.*' \
  -o -name '*.tfplan' -o -name '__pycache__' \) -prune -exec rm -rf {} +
project=$ref/codeorca.yaml
cd "$work"   # nothing runs with the checkout as its cwd
export CODEORCA_REDACTION_KEY=example-not-secret-smoke

step "codeorca doctor matches the reference runtime: block"
if ! codeorca doctor -p "$project"; then fail "codeorca doctor reports drift from examples/reference/codeorca.yaml runtime:"; fi

step "codeorca validate"
if ! codeorca validate "$ref"/workflows/*.yaml; then fail "the reference workflows do not validate"; fi

step "run plan-only"
if ! codeorca run plan-only -p "$project" < /dev/null; then fail "plan-only did not exit 0"; fi

step "run configure-local"
if ! codeorca run configure-local -p "$project" --input "config_dir=$work/config" < /dev/null; then
  fail "configure-local did not exit 0"
fi
if [ ! -s "$work/config/app.conf" ]; then fail "configure-local did not write $work/config/app.conf"; fi

step "run demo-rollout stops at the gate (exit 3)"
set +e
codeorca run demo-rollout -p "$project" --input "config_dir=$work/config-demo" < /dev/null
rc=$?
set -e
if [ "$rc" -ne 3 ]; then fail "demo-rollout exited $rc, want 3 (waiting at the gate)"; fi

step "resume --approve refuses without a terminal"
set +e
codeorca resume latest --approve -p "$project" < /dev/null > "$work/resume.out" 2> "$work/resume.err"
rc=$?
set -e
cat "$work/resume.out" "$work/resume.err"
if [ "$rc" -eq 0 ]; then fail "resume --approve succeeded without a terminal"; fi
if ! grep -q "needs an interactive terminal" "$work/resume.err"; then fail "resume did not print the terminal refusal"; fi
if ! python3 - "$ref/.codeorca/runs" <<'PY'
import json
import sys
from pathlib import Path

runs = [json.loads(p.read_text()) for p in Path(sys.argv[1]).glob("*/run.json")]
demo = max((r for r in runs if r.get("workflow") == "demo-rollout"), key=lambda r: r["started"])
sys.exit(0 if demo["status"] == "waiting" else f"demo-rollout run.json is {demo['status']!r} after a refused resume")
PY
then fail "the refused resume changed the run"; fi

step "lint powershell, lint ansible"
if ! codeorca lint powershell "$ref/helpers"; then fail "codeorca lint powershell failed on the reference helpers"; fi
if ! codeorca lint powershell --ansible-settings "$ref/helpers"; then fail "codeorca lint powershell --ansible-settings failed"; fi
if ! codeorca lint ansible -p "$project" "$ref/ansible"; then fail "codeorca lint ansible failed on the reference playbooks"; fi

step "no placeholder secret in the produced files"
for f in specs/app/plan.yaml specs/app/plan.meta.yaml specs/app/hosts/app-host.yaml specs/app/hosts/app-host.meta.yaml; do
  if [ ! -s "$ref/$f" ]; then fail "$f was not produced (the leak check below would be vacuous)"; fi
done
for pattern in FIXTURE-SECRET example-not-secret-smoke; do
  if grep -raq -- "$pattern" "$ref/specs" "$ref/.codeorca"; then
    grep -ral -- "$pattern" "$ref/specs" "$ref/.codeorca" >&2
    fail "placeholder secret leaked into the produced files: $pattern"
  fi
done

echo "PASS: code-orca ${pkg_have} | terraform ${tf_have} | pwsh ${pwsh_want} | PSScriptAnalyzer ${pssa_have} | ansible-core ${core_have} | python $(python3 -c 'import platform; print(platform.python_version())') | reference: doctor, plan-only, configure-local, demo-rollout gate (3), resume refused, lint, no leak"
