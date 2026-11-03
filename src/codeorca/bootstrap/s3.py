"""S3 state-backend bootstrap (plan section 5.11): idempotent, re-runnable, dry-run aware, boto3 only.

``python -m codeorca.bootstrap.s3 --project codeorca.yaml [--dry-run] [--output-file path]``

1. Refuse unless the project's ``backend.type`` is ``s3`` (a local backend has nothing to bootstrap) and
   ``sts get-caller-identity`` returns ``backend.account_id`` (a wrong credential profile cannot create the bucket
   in another account).
2. Create the bucket if absent (``CreateBucketConfiguration`` with the region; ``us-east-1`` takes none). An existing
   bucket must answer ``HeadBucket`` for this account and sit in ``backend.region``; a bucket whose Object Lock has a
   **default retention** is refused before anything is written (an undeletable ``.tflock`` would never release).
   Object Lock without a default retention is allowed and noted as unverified (plan section 10, V15).
3. Converge, in order, comparing each setting before writing it: public access block (all four true), versioning
   ``Enabled``, default encryption (``AES256``, or ``aws:kms`` with the key of ``backend.encryption: kms:<arn>`` and
   an S3 bucket key), a bucket-policy statement (Sid :data:`POLICY_SID`) denying ``aws:SecureTransport=false``
   (merged: other statements are kept), a lifecycle rule (ID :data:`LIFECYCLE_RULE_ID`) expiring noncurrent versions
   after ``backend.noncurrent_version_expiry_days`` (merged by rule ID), the tag ``managed-by=code-orca`` (merged).
4. Write each stack's ``backend.hcl`` (bucket, key, region, ``use_lockfile = true``, ``encrypt = true``,
   ``kms_key_id`` under kms) into the stack directory, so ``terraform init -backend-config=backend.hcl`` is
   reproducible from the repo. Never credentials.

The output (``--output-file``, defaulting to ``$CODEORCA_OUTPUT_FILE``; stdout otherwise) is JSON:
``{bucket, region, account_id, created, changed: [...], dry_run, backend_files: [...], diff: {setting: {before,
after}}, notes: [...]}``. Nothing in it is secret: settings, the bucket's own name, a KMS key ARN. A replaced
``backend.hcl`` appears as ``{sha256, bytes}`` before and the new (settings-only) text after: the previous file's
content is never copied (a hand-written one can hold credentials; a note says so when it looks like it did). Under
``--dry-run`` (or ``CODEORCA_DRY_RUN=1``, which the python step sets) nothing is written, in AWS or on disk, and the
diff is what a real run would change.

Guardrails: the helper never lists, reads or writes objects (state lives there); every AWS call is time-limited
(botocore ``connect_timeout``/``read_timeout``, ``retries={'max_attempts': 2}`` and a wall-clock deadline that also
covers a hung credential provider); errors carry an AWS error code, never a response body. Needed permissions:
``sts:GetCallerIdentity``, ``s3:CreateBucket``, ``s3:ListBucket`` (HeadBucket), ``s3:GetBucketLocation``,
``s3:Get/PutBucketPublicAccessBlock``, ``s3:Get/PutBucketVersioning``, ``s3:Get/PutEncryptionConfiguration``,
``s3:Get/PutBucketPolicy``, ``s3:Get/PutLifecycleConfiguration``, ``s3:GetBucketObjectLockConfiguration``,
``s3:Get/PutBucketTagging``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from codeorca.adapters.terraform import CREDENTIAL_KEY_PATTERN
from codeorca.project import Backend, Project, Stack, load_project
from codeorca.providers.ssm import aws_config, boto3_available, call_with_deadline, describe_error

POLICY_SID = "CodeOrcaDenyInsecureTransport"
LIFECYCLE_RULE_ID = "codeorca-noncurrent-version-expiry"
MANAGED_TAG = ("managed-by", "code-orca")
PUBLIC_ACCESS_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
BACKEND_FILE = "backend.hcl"

# "absent" answers for each read: the setting is simply not configured yet
_ABSENT_CODES = {
    "get_public_access_block": {"NoSuchPublicAccessBlockConfiguration"},
    "get_bucket_encryption": {"ServerSideEncryptionConfigurationNotFoundError"},
    "get_bucket_policy": {"NoSuchBucketPolicy"},
    "get_bucket_lifecycle_configuration": {"NoSuchLifecycleConfiguration"},
    "get_object_lock_configuration": {"ObjectLockConfigurationNotFoundError"},
    "get_bucket_tagging": {"NoSuchTagSet"},
}
_NOT_FOUND = {"404", "NoSuchBucket", "NotFound"}


class BootstrapError(RuntimeError):
    """The bootstrap refused or failed; the message carries no secret (codes, names, settings only)."""


# --------------------------------------------------------------------------------------------------- desired state
def kms_key_arn(backend: Backend) -> str | None:
    return backend.encryption[len("kms:") :] if backend.encryption.startswith("kms:") else None


def backend_settings(project: Project, stack: Stack) -> dict[str, object]:
    """The non-secret backend configuration of one stack: what ``backend.hcl`` holds and what the terraform step
    passes as ``-backend-config`` (``kms_key_id`` only under ``encryption: kms:<arn>``)."""
    backend = project.backend
    settings: dict[str, object] = {
        "bucket": backend.bucket,
        "key": stack.key,
        "region": backend.region,
        "use_lockfile": True,
        "encrypt": True,
    }
    kms = kms_key_arn(backend)
    if kms:
        settings["kms_key_id"] = kms
    return settings


def _hcl_string(value: str) -> str:
    # JSON string escaping is valid HCL; template sequences must not be interpreted
    return json.dumps(value).replace("${", "$${").replace("%{", "%%{")


def render_backend_hcl(settings: dict[str, object]) -> str:
    width = max(len(k) for k in settings)
    lines = [
        "# Generated by code-orca (python -m codeorca.bootstrap.s3); non-secret backend settings only.",
        "# terraform init -backend-config=backend.hcl. Edit codeorca.yaml's backend: block and re-run instead.",
    ]
    for key, value in settings.items():
        text = ("true" if value else "false") if isinstance(value, bool) else _hcl_string(str(value))
        lines.append(f"{key.ljust(width)} = {text}")
    return "\n".join(lines) + "\n"


def _file_digest(data: bytes | None) -> dict[str, Any] | None:
    if data is None:
        return None
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


_CREDENTIAL_LINE = re.compile(
    r"^\s*\w*(" + CREDENTIAL_KEY_PATTERN.pattern.removeprefix("(?i)") + r")\w*\s*=", re.IGNORECASE | re.MULTILINE
)


def desired_policy_statement(bucket: str) -> dict[str, Any]:
    arn = f"arn:aws:s3:::{bucket}"
    return {
        "Sid": POLICY_SID,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [arn, f"{arn}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }


def desired_lifecycle_rule(days: int) -> dict[str, Any]:
    return {
        "ID": LIFECYCLE_RULE_ID,
        "Status": "Enabled",
        "Filter": {"Prefix": ""},
        "NoncurrentVersionExpiration": {"NoncurrentDays": days},
    }


def desired_encryption(backend: Backend) -> dict[str, Any]:
    kms = kms_key_arn(backend)
    if kms:
        return {"algorithm": "aws:kms", "kms_key_id": kms, "bucket_key_enabled": True}
    return {"algorithm": "AES256", "kms_key_id": None}


# --------------------------------------------------------------------------------------------------- normalisers
def _as_list(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _norm_statement(statement: dict | None) -> dict | None:
    """Comparable form of a policy statement: singleton strings and lists compare equal, order does not matter."""
    if statement is None:
        return None
    out: dict[str, Any] = {}
    for key, value in statement.items():
        if key in ("Action", "NotAction", "Resource", "NotResource"):
            out[key] = sorted(str(v) for v in _as_list(value))
        elif key == "Principal" and isinstance(value, dict):
            out[key] = {k: sorted(str(v) for v in _as_list(v)) for k, v in value.items()}
        else:
            out[key] = value
    return json.loads(json.dumps(out, sort_keys=True))


def _norm_rule(rule: dict | None) -> dict | None:
    if rule is None:
        return None
    prefix = (rule.get("Filter") or {}).get("Prefix", rule.get("Prefix", ""))
    return {
        "status": rule.get("Status"),
        "filter_prefix": prefix or "",
        "noncurrent_days": (rule.get("NoncurrentVersionExpiration") or {}).get("NoncurrentDays"),
    }


def _norm_encryption(rules: list[dict], desired: dict[str, Any]) -> dict[str, Any] | None:
    if not rules:
        return None
    rule = rules[0]
    default = rule.get("ApplyServerSideEncryptionByDefault") or {}
    out: dict[str, Any] = {"algorithm": default.get("SSEAlgorithm"), "kms_key_id": default.get("KMSMasterKeyID")}
    if "bucket_key_enabled" in desired:
        out["bucket_key_enabled"] = bool(rule.get("BucketKeyEnabled", False))
    return out


# --------------------------------------------------------------------------------------------------- AWS wrapper
class _Aws:
    """Time-limited calls; ``ClientError`` codes stay readable for the caller, nothing else of a response."""

    def __init__(self, session_factory: Callable[[], Any], region: str, timeout_s: float) -> None:
        self.timeout_s = timeout_s
        self.deadline_s = 4 * timeout_s
        try:
            self.session = call_with_deadline(session_factory, self.deadline_s, "aws session", BootstrapError)
        except BootstrapError:
            raise
        except Exception as e:  # noqa: BLE001 - a profile or credential error, by class name only
            raise BootstrapError(f"could not create an AWS session: {describe_error(e)}") from None
        self.config = aws_config(timeout_s)
        self.s3 = self.session.client("s3", region_name=region, config=self.config)
        self.sts = self.session.client("sts", region_name=region, config=self.config)

    def s3_call(self, op: str, **kwargs) -> Any:
        return self.call(self.s3, "s3", op, **kwargs)

    def call(self, client: Any, service: str, op: str, **kwargs) -> Any:
        return call_with_deadline(
            lambda: getattr(client, op)(**kwargs), self.deadline_s, f"{service} {op}", BootstrapError
        )

    def read(self, op: str, bucket: str) -> Any:
        """A ``get_*`` read; ``None`` when the setting is not configured (its documented absent code)."""
        try:
            return self.s3_call(op, Bucket=bucket)
        except BootstrapError:
            raise
        except Exception as e:  # noqa: BLE001 - classified by code, re-raised value-free
            if error_code(e) in _ABSENT_CODES.get(op, set()):
                return None
            raise BootstrapError(f"s3 {op} on {bucket} failed: {describe_error(e)}") from None


def error_code(e: BaseException) -> str | None:
    response = getattr(e, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code")
        return str(code) if code is not None else None
    return None


def _write(aws: _Aws, op: str, **kwargs) -> None:
    try:
        aws.s3_call(op, **kwargs)
    except BootstrapError:
        raise
    except Exception as e:  # noqa: BLE001
        raise BootstrapError(f"s3 {op} on {kwargs.get('Bucket')} failed: {describe_error(e)}") from None


# --------------------------------------------------------------------------------------------------- converge
def _default_session_factory(region: str) -> Callable[[], Any]:
    def factory():
        import boto3

        return boto3.Session(region_name=region)

    return factory


def bootstrap(
    project: Project,
    *,
    dry_run: bool = False,
    session_factory: Callable[[], Any] | None = None,
    timeout_s: float = 10,
) -> dict[str, Any]:
    """Converge the bucket and the stacks' ``backend.hcl`` files; returns the output document."""
    backend = project.backend
    if backend.type != "s3":
        raise BootstrapError(
            f"backend.type is {backend.type!r}: the bootstrap creates an s3 backend only; a local backend has nothing "
            "to bootstrap (set backend.type: s3 with bucket, region and account_id in codeorca.yaml)"
        )
    assert backend.bucket and backend.region and backend.account_id  # the project model guarantees these for s3
    if project.root is None:
        raise BootstrapError("the project has no root directory (load it with load_project)")
    # every stack directory must exist before anything in AWS is touched
    targets: list[tuple[str, Path]] = []
    for name in project.stack_order():
        stack_dir = (project.root / project.stacks[name].dir).resolve()
        if not stack_dir.is_dir():
            raise BootstrapError(f"stacks.{name}: directory {project.stacks[name].dir} does not exist")
        target = stack_dir / BACKEND_FILE
        if target.is_symlink():
            raise BootstrapError(f"stacks.{name}: {BACKEND_FILE} is a symlink; refusing to write through it")
        targets.append((name, target))

    if session_factory is None:
        if not boto3_available():
            raise BootstrapError("boto3 is not installed; install the aws extra: pip install 'code-orca[aws]'")
        session_factory = _default_session_factory(backend.region)
    aws = _Aws(session_factory, backend.region, timeout_s)
    bucket = backend.bucket

    # 1. the caller must be the backend's account
    try:
        identity = aws.call(aws.sts, "sts", "get_caller_identity")
    except BootstrapError:
        raise
    except Exception as e:  # noqa: BLE001
        raise BootstrapError(f"sts get_caller_identity failed: {describe_error(e)}") from None
    caller = str(identity.get("Account"))
    if caller != backend.account_id:
        raise BootstrapError(
            f"caller account {caller} is not backend.account_id {backend.account_id}: refusing (wrong credential "
            "profile?)"
        )

    diff: dict[str, dict[str, Any]] = {}
    changed: list[str] = []
    notes: list[str] = []

    def record(setting: str, before: Any, after: Any) -> bool:
        if before == after:
            return False
        diff[setting] = {"before": before, "after": after}
        changed.append(setting)
        return True

    # 2. existence, ownership, region, Object Lock
    exists = _bucket_exists(aws, bucket, backend.account_id)
    created = not exists
    if exists:
        _check_region(aws, bucket, backend.region)
        _check_object_lock(aws, bucket, notes)
    else:
        record("bucket", None, {"name": bucket, "region": backend.region})
        if not dry_run:
            kwargs: dict[str, Any] = {"Bucket": bucket}
            if backend.region != "us-east-1":
                kwargs["CreateBucketConfiguration"] = {"LocationConstraint": backend.region}
            _write(aws, "create_bucket", **kwargs)
            exists = True
    live = exists  # under --dry-run an absent bucket has nothing to read: every setting is "before: None"

    def read(op: str) -> Any:
        return aws.read(op, bucket) if live else None

    # 3a. public access block
    got = read("get_public_access_block")
    before = None
    if got is not None:
        conf = got.get("PublicAccessBlockConfiguration") or {}
        before = {k: bool(conf.get(k, False)) for k in PUBLIC_ACCESS_KEYS}
    desired_pab = dict.fromkeys(PUBLIC_ACCESS_KEYS, True)
    if record("public_access_block", before, desired_pab) and not dry_run:
        _write(aws, "put_public_access_block", Bucket=bucket, PublicAccessBlockConfiguration=desired_pab)

    # 3b. versioning
    got = read("get_bucket_versioning")
    before = (got or {}).get("Status")
    if record("versioning", before, "Enabled") and not dry_run:
        _write(aws, "put_bucket_versioning", Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    # 3c. default encryption
    want = desired_encryption(backend)
    got = read("get_bucket_encryption")
    rules = ((got or {}).get("ServerSideEncryptionConfiguration") or {}).get("Rules") or []
    if record("encryption", _norm_encryption(rules, want), want) and not dry_run:
        default: dict[str, Any] = {"SSEAlgorithm": want["algorithm"]}
        rule: dict[str, Any] = {"ApplyServerSideEncryptionByDefault": default}
        if want["kms_key_id"]:
            default["KMSMasterKeyID"] = want["kms_key_id"]
            rule["BucketKeyEnabled"] = True
        _write(aws, "put_bucket_encryption", Bucket=bucket, ServerSideEncryptionConfiguration={"Rules": [rule]})

    # 3d. bucket policy: our statement by Sid, every other statement kept
    got = read("get_bucket_policy")
    document: dict[str, Any] = {"Version": "2012-10-17", "Statement": []}
    if got is not None and got.get("Policy"):
        try:
            document = json.loads(got["Policy"])
        except (TypeError, ValueError):
            raise BootstrapError(
                f"the bucket policy of {bucket} is not valid JSON; refusing to merge into it"
            ) from None
    statements = _as_list(document.get("Statement"))
    ours = next((s for s in statements if isinstance(s, dict) and s.get("Sid") == POLICY_SID), None)
    want_statement = desired_policy_statement(bucket)
    if record("bucket_policy", _norm_statement(ours), _norm_statement(want_statement)) and not dry_run:
        merged = [s for s in statements if not (isinstance(s, dict) and s.get("Sid") == POLICY_SID)]
        document["Statement"] = [*merged, want_statement]
        document.setdefault("Version", "2012-10-17")
        _write(aws, "put_bucket_policy", Bucket=bucket, Policy=json.dumps(document))

    # 3e. lifecycle: our rule by ID, every other rule kept
    got = read("get_bucket_lifecycle_configuration")
    existing_rules = list((got or {}).get("Rules") or [])
    ours_rule = next((r for r in existing_rules if r.get("ID") == LIFECYCLE_RULE_ID), None)
    want_rule = desired_lifecycle_rule(backend.noncurrent_version_expiry_days)
    if record("lifecycle", _norm_rule(ours_rule), _norm_rule(want_rule)) and not dry_run:
        merged_rules = [r for r in existing_rules if r.get("ID") != LIFECYCLE_RULE_ID] + [want_rule]
        kwargs = {"Bucket": bucket, "LifecycleConfiguration": {"Rules": merged_rules}}
        if got and got.get("TransitionDefaultMinimumObjectSize"):
            kwargs["TransitionDefaultMinimumObjectSize"] = got["TransitionDefaultMinimumObjectSize"]
        _write(aws, "put_bucket_lifecycle_configuration", **kwargs)

    # 3f. tags: ours merged into the existing set
    got = read("get_bucket_tagging")
    tag_set = list((got or {}).get("TagSet") or [])
    current = {t.get("Key"): t.get("Value") for t in tag_set}
    tag_key, tag_value = MANAGED_TAG
    before = {tag_key: current[tag_key]} if tag_key in current else None
    if record("tags", before, {tag_key: tag_value}) and not dry_run:
        merged_tags = [t for t in tag_set if t.get("Key") != tag_key] + [{"Key": tag_key, "Value": tag_value}]
        _write(aws, "put_bucket_tagging", Bucket=bucket, Tagging={"TagSet": merged_tags})

    # 4. backend.hcl per stack
    backend_files: list[str] = []
    for name, target in targets:
        text = render_backend_hcl(backend_settings(project, project.stacks[name]))
        previous = target.read_bytes() if target.exists() else None
        rel = os.path.relpath(target, project.root)
        backend_files.append(rel)
        if previous == text.encode("utf-8"):
            continue
        # the previous file is described by digest and size only: a hand-written backend.hcl can hold credentials
        # (the very thing this file replaces), and the diff lands in output.json, result.json and run.json
        record(f"backend_file:{name}", _file_digest(previous), text)
        if previous is not None and _CREDENTIAL_LINE.search(previous.decode("utf-8", "replace")):
            notes.append(
                f"backend_file:{name}: the previous {rel} held credential-looking settings; they are gone from the "
                "file (rotate them if it was ever committed); credentials belong in the environment"
            )
        if not dry_run:
            _atomic_write(target, text)

    return {
        "bucket": bucket,
        "region": backend.region,
        "account_id": backend.account_id,
        "created": created,
        "changed": changed,
        "dry_run": dry_run,
        "backend_files": backend_files,
        "diff": diff,
        "notes": notes,
    }


def _bucket_exists(aws: _Aws, bucket: str, account_id: str) -> bool:
    try:
        aws.s3_call("head_bucket", Bucket=bucket, ExpectedBucketOwner=account_id)
        return True
    except BootstrapError:
        raise
    except Exception as e:  # noqa: BLE001
        code = error_code(e)
        if code in _NOT_FOUND:
            return False
        if code in ("403", "AccessDenied", "Forbidden"):
            raise BootstrapError(
                f"bucket {bucket} exists but is not accessible to account {account_id} (owned by another account, or "
                "the credentials lack s3:ListBucket): refusing"
            ) from None
        raise BootstrapError(f"s3 head_bucket on {bucket} failed: {describe_error(e)}") from None


def _check_region(aws: _Aws, bucket: str, region: str) -> None:
    try:
        got = aws.s3_call("get_bucket_location", Bucket=bucket)
    except BootstrapError:
        raise
    except Exception as e:  # noqa: BLE001
        raise BootstrapError(f"s3 get_bucket_location on {bucket} failed: {describe_error(e)}") from None
    location = got.get("LocationConstraint") or "us-east-1"
    if location == "EU":
        location = "eu-west-1"
    if location != region:
        raise BootstrapError(f"bucket {bucket} is in {location}, not backend.region {region}: refusing")


def _check_object_lock(aws: _Aws, bucket: str, notes: list[str]) -> None:
    got = aws.read("get_object_lock_configuration", bucket)
    conf = (got or {}).get("ObjectLockConfiguration") or {}
    if conf.get("ObjectLockEnabled") != "Enabled":
        return
    if (conf.get("Rule") or {}).get("DefaultRetention"):
        raise BootstrapError(
            f"bucket {bucket} has an Object Lock default retention: Terraform's .tflock object could never be "
            "deleted, so the state lock would never release; refusing (use a bucket without a default retention)"
        )
    notes.append(
        "object lock is enabled without a default retention: allowed, but unverified with use_lockfile (plan "
        "section 10, V15)"
    )


def _atomic_write(target: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".backend.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)  # committed, non-secret configuration
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------------------------------- CLI
def _summary(result: dict[str, Any]) -> str:
    head = "would change" if result["dry_run"] else "changed"
    lines = [
        f"backend bucket {result['bucket']} ({result['region']}, account {result['account_id']}): "
        + (f"{head}: {', '.join(result['changed'])}" if result["changed"] else "already converged")
    ]
    for setting in result["changed"]:
        if setting.startswith("backend_file:"):
            lines.append(f"  {setting}")
            continue
        entry = result["diff"][setting]
        lines.append(f"  {setting}: {json.dumps(entry['before'])} -> {json.dumps(entry['after'])}")
    lines.extend(f"  note: {note}" for note in result["notes"])
    return "\n".join(lines)


def main(argv: list[str] | None = None, *, session_factory: Callable[[], Any] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m codeorca.bootstrap.s3", description=__doc__.splitlines()[0])
    parser.add_argument("--project", default="codeorca.yaml", help="the project file (default: ./codeorca.yaml)")
    parser.add_argument(
        "--dry-run", action="store_true", default=os.environ.get("CODEORCA_DRY_RUN") == "1", help="write nothing"
    )
    parser.add_argument(
        "--output-file", default=os.environ.get("CODEORCA_OUTPUT_FILE"), help="JSON result (default: stdout)"
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="per-call AWS connect/read timeout, seconds")
    args = parser.parse_args(argv)
    try:
        project = load_project(args.project)
        result = bootstrap(project, dry_run=args.dry_run, session_factory=session_factory, timeout_s=args.timeout)
    except BootstrapError as e:
        print(f"bootstrap refused: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f"bootstrap failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    document = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output_file:
        Path(args.output_file).write_text(document, encoding="utf-8")
        print(_summary(result))
    else:
        sys.stdout.write(document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
