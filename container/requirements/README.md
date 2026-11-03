# container/requirements

Python pins for `container/Dockerfile`, generated, never edited by hand.

| File | What |
|---|---|
| `codeorca.in` | code-orca's runtime dependencies the base image (`ghcr.io/git-cgallagher/ansible-runtime`) does **not** already install, one per line with a why/who comment. Empty today: the base pins every one (jinja2, pydantic, ruamel.yaml, ansible-core, boto3) |
| `codeorca.txt` | its hash-pinned lock, installed with `pip install --require-hashes --no-deps -c /usr/share/ansible-runtime/constraints.txt` |
| `build.in` / `build.txt` | the wheel's build backend (setuptools), hash-pinned, for the builder stage only (never shipped) |
| `lock.sh` | regenerates both `.txt` files |

Regenerate after editing a `.in` file or bumping `BASE_IMAGE` (the base's pins can move):

```bash
container/requirements/lock.sh
```

It runs, inside the image `ARG BASE_IMAGE=` names (so the hashes and markers resolve for that Python on Linux):

```bash
pip install pip-tools
pip-compile --generate-hashes --allow-unsafe --strip-extras \
  --constraint=/usr/share/ansible-runtime/constraints.txt \
  --output-file=container/requirements/<name>.txt container/requirements/<name>.in
```

The `--constraint` is the shared dependency model (ansible-runtime `docs/SHARED-DEPENDENCIES.md`): a package the
base already pins can only resolve to the base's version, and a pin here that disagrees with a later base makes
the image build fail (`ResolutionImpossible`) instead of silently moving the base's package.
