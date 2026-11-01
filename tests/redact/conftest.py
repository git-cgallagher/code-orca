"""Shared fixtures for the redaction tests. No test here needs a ``terraform`` or ``ansible`` binary.

Every secret-shaped value in ``fixtures/`` is a placeholder named ``FIXTURE-SECRET-*`` / ``FIXTURE-EPHEMERAL-*``.

How ``fixtures/`` was made (Terraform 1.14.7, 2026-11-01), so it can be regenerated:

* ``plan.json``, ``state.json``, ``output.json`` come from this provider-free stack (``hashicorp/random`` only)::

      variable "db_password" { type = string  sensitive = true  default = "FIXTURE-SECRET-abc123" }
      variable "eph_token"   { type = string  ephemeral = true  default = "FIXTURE-EPHEMERAL-xyz" }
      resource "random_password" "pw" { length = 12 }
      resource "terraform_data" "t"   { input = { pw = var.db_password, plain = "hello" } }
      resource "terraform_data" "eph" { input = "x"
        provisioner "local-exec" { command = "echo ${var.eph_token} > /dev/null" } }
      output "pw_out"          { value = var.db_password  sensitive = true }
      output "pw_nonsensitive" { value = nonsensitive(var.db_password) }
      output "plain"           { value = "hello" }

  in a temporary directory: ``terraform init``, then ``terraform plan -out=p.tfplan`` **before any apply** and
  ``terraform show -json p.tfplan > plan.json`` (create actions, real ``after_unknown``); then
  ``terraform apply -auto-approve``, ``terraform show -json > state.json`` (piped, the ``.tfstate`` file is never
  read) and ``terraform output -json > output.json``. Hand edits: the random provider's generated ``result``
  and ``bcrypt_hash`` were replaced by ``FIXTURE-SECRET-random-result`` / ``FIXTURE-SECRET-bcrypt-hash-placeholder``
  and the JSON was re-dumped with sorted keys.
* ``providers-schema.json`` is ``terraform providers schema -json`` from that stack, cut down to
  ``random_password`` and ``terraform_data``, plus a hand-written ``registry.terraform.io/example/example``
  provider that has the shapes real cloud providers emit (``nested_type``, ``block_types``, ``write_only``, a
  sensitive provider attribute, a data source, an ephemeral resource).
* ``ansible-stdout.log`` is the captured, colourised stdout of a playbook (ansible-core 2.21.5, ``-vvv``) whose
  tasks print a secret-bearing var with and without ``no_log`` and ``fail:`` with the secret in ``msg``.
* ``terraform-trace.log`` is a ``TF_LOG=trace`` JSON-lines excerpt from ``terraform plan`` on the stack above
  (local paths replaced by ``/home/example``): the ``UpgradeResourceState`` lines carry the secret JSON-escaped.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from pathlib import Path

import pytest

from codeorca.redact import SecretRegistry

FIXTURES = Path(__file__).parent / "fixtures"
KEY = b"example-hmac-key-not-secret"
KEY_ID = "ssm:/codeorca/redaction-key@1"

# Every placeholder secret the fixtures contain (see the grep in the acceptance test) plus the ones a run would
# declare in its project file (``secrets:``) or register from vaulted / ephemeral values.
FIXTURE_SECRETS = (
    "FIXTURE-SECRET-abc123",
    "FIXTURE-EPHEMERAL-xyz",
    "FIXTURE-SECRET-bcrypt-hash-placeholder",
    "FIXTURE-SECRET-random-result",
    "FIXTURE-SECRET-token-999",
    "FIXTURE-SECRET-vaulted",
    "FIXTURE-SECRET-loop1",
    "FIXTURE-SECRET-argv",
)


def encodings(value: str) -> dict[str, str]:
    """The four forms the acceptance criterion names, computed independently of the package."""
    return {
        "raw": value,
        "json": json.dumps(value)[1:-1],
        "url": urllib.parse.quote(value, safe=""),
        "base64": base64.b64encode(value.encode()).decode(),
    }


@pytest.fixture
def key() -> bytes:
    return KEY


@pytest.fixture
def key_id() -> str:
    return KEY_ID


@pytest.fixture
def fixture_secrets() -> tuple[str, ...]:
    return FIXTURE_SECRETS


@pytest.fixture
def encode():
    return encodings


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def registry() -> SecretRegistry:
    return SecretRegistry(KEY, KEY_ID)


@pytest.fixture
def load_json():
    def _load(name: str):
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    return _load
