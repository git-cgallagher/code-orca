"""The S3 backend bootstrap over moto: create + converge, idempotence, dry-run, refusals, merges, backend.hcl."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import boto3
import pytest

from codeorca.bootstrap import s3 as bootstrap_s3
from codeorca.bootstrap.s3 import (
    LIFECYCLE_RULE_ID,
    POLICY_SID,
    BootstrapError,
    bootstrap,
    main,
    render_backend_hcl,
)
from codeorca.config import load_yaml
from codeorca.project import load_project

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference" / "codeorca.yaml"
ACCOUNT = "123456789012"  # moto's caller identity
BUCKET = "example-tfstate-123456789012"
KMS_ARN = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
SETTINGS = ["public_access_block", "versioning", "encryption", "bucket_policy", "lifecycle", "tags"]


def write_project(tmp_path: Path, **backend) -> Path:
    """The reference project with an s3 backend and two stacks (``net`` <- ``app``) under ``tmp_path``."""
    data = load_yaml(REFERENCE)
    data["backend"] = {
        "type": "s3",
        "account_id": ACCOUNT,
        "bucket": BUCKET,
        "region": "us-east-1",
        "noncurrent_version_expiry_days": 30,
        **backend,
    }
    app = data["stacks"]["app"]
    data["stacks"] = {
        "net": {**app, "dir": "terraform/net", "key": "example/net/terraform.tfstate"},
        "app": {**app, "dir": "terraform/app", "depends_on": ["net"]},
    }
    for stack in data["stacks"].values():
        (tmp_path / stack["dir"]).mkdir(parents=True, exist_ok=True)
    path = tmp_path / "codeorca.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")  # JSON is YAML 1.2
    return path


def s3(region: str = "us-east-1"):
    return boto3.client("s3", region_name=region)


class Recording:
    """A real boto3 Session that records every operation its clients make and the config they were built with."""

    def __init__(self, region: str = "us-east-1") -> None:
        self.session = boto3.Session(region_name=region)
        self.ops: list[str] = []
        self.configs: list = []

    def __call__(self):
        return self

    def client(self, service, **kwargs):
        self.configs.append((service, kwargs.get("config")))
        client = self.session.client(service, **kwargs)
        client.meta.events.register("before-call.*.*", self._record)
        return client

    def _record(self, model, **_):
        self.ops.append(model.name)


def test_creates_and_converges_every_setting(tmp_path):
    project = load_project(write_project(tmp_path))
    result = bootstrap(project)
    assert result["created"] is True and result["dry_run"] is False
    assert result["bucket"] == BUCKET and result["account_id"] == ACCOUNT and result["region"] == "us-east-1"
    assert "bucket" in result["changed"]
    for setting in ("public_access_block", "versioning", "bucket_policy", "lifecycle", "tags"):
        assert setting in result["changed"], setting
    client = s3()
    pab = client.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
    assert all(pab[k] for k in bootstrap_s3.PUBLIC_ACCESS_KEYS)
    assert client.get_bucket_versioning(Bucket=BUCKET)["Status"] == "Enabled"
    enc = client.get_bucket_encryption(Bucket=BUCKET)["ServerSideEncryptionConfiguration"]["Rules"][0]
    assert enc["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"
    policy = json.loads(client.get_bucket_policy(Bucket=BUCKET)["Policy"])
    (ours,) = [s for s in policy["Statement"] if s.get("Sid") == POLICY_SID]
    assert ours["Effect"] == "Deny" and ours["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    rules = client.get_bucket_lifecycle_configuration(Bucket=BUCKET)["Rules"]
    (rule,) = [r for r in rules if r["ID"] == LIFECYCLE_RULE_ID]
    assert rule["NoncurrentVersionExpiration"]["NoncurrentDays"] == 30 and rule["Status"] == "Enabled"
    tags = {t["Key"]: t["Value"] for t in client.get_bucket_tagging(Bucket=BUCKET)["TagSet"]}
    assert tags == {"managed-by": "code-orca"}
    assert result["backend_files"] == ["terraform/net/backend.hcl", "terraform/app/backend.hcl"]  # depends_on order


def test_second_run_changes_nothing(tmp_path):
    project = load_project(write_project(tmp_path))
    bootstrap(project)
    again = bootstrap(project)
    assert again["changed"] == [] and again["diff"] == {} and again["created"] is False


def test_dry_run_on_an_absent_bucket_writes_nothing(tmp_path):
    project = load_project(write_project(tmp_path))
    result = bootstrap(project, dry_run=True)
    assert result["dry_run"] is True and result["created"] is True
    assert set(SETTINGS) <= set(result["changed"])
    assert all(result["diff"][s]["before"] is None for s in SETTINGS)
    assert result["diff"]["versioning"]["after"] == "Enabled"
    assert s3().list_buckets()["Buckets"] == []
    assert not (tmp_path / "terraform/app/backend.hcl").exists()
    assert not (tmp_path / "terraform/net/backend.hcl").exists()
    assert result["backend_files"] == ["terraform/net/backend.hcl", "terraform/app/backend.hcl"]


def test_dry_run_on_a_drifted_bucket_reports_and_leaves_it(tmp_path):
    project = load_project(write_project(tmp_path))
    bootstrap(project)
    s3().put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Suspended"})
    (tmp_path / "terraform/app/backend.hcl").write_text("# hand edited\n")
    result = bootstrap(project, dry_run=True)
    assert result["changed"] == ["versioning", "backend_file:app"]
    assert result["diff"]["versioning"] == {"before": "Suspended", "after": "Enabled"}
    assert s3().get_bucket_versioning(Bucket=BUCKET)["Status"] == "Suspended"
    assert (tmp_path / "terraform/app/backend.hcl").read_text() == "# hand edited\n"
    fixed = bootstrap(project)
    assert fixed["changed"] == ["versioning", "backend_file:app"]
    assert bootstrap(project)["changed"] == []


def test_refuses_the_wrong_account_before_creating_anything(tmp_path):
    project = load_project(write_project(tmp_path, account_id="210987654321"))
    with pytest.raises(BootstrapError) as e:
        bootstrap(project)
    assert "210987654321" in str(e.value) and ACCOUNT in str(e.value)
    assert s3().list_buckets()["Buckets"] == []
    assert not (tmp_path / "terraform/app/backend.hcl").exists()


def test_refuses_a_default_retention_object_lock_bucket_and_writes_nothing(tmp_path):
    client = s3()
    client.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    client.put_object_lock_configuration(
        Bucket=BUCKET,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
        },
    )
    project = load_project(write_project(tmp_path))
    with pytest.raises(BootstrapError) as e:
        bootstrap(project)
    assert "default retention" in str(e.value)
    with pytest.raises(client.exceptions.ClientError):
        client.get_bucket_tagging(Bucket=BUCKET)  # nothing converged
    assert not (tmp_path / "terraform/app/backend.hcl").exists()


def test_object_lock_without_default_retention_is_allowed_and_noted(tmp_path):
    s3().create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    result = bootstrap(load_project(write_project(tmp_path)))
    assert result["created"] is False
    assert any("unverified" in note for note in result["notes"])


def test_merges_an_existing_policy_lifecycle_and_tags_without_dropping_foreign_entries(tmp_path):
    client = s3()
    client.create_bucket(Bucket=BUCKET)
    foreign_statement = {
        "Sid": "ExampleReadOnly",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/example-reader"},
        "Action": "s3:GetBucketLocation",
        "Resource": f"arn:aws:s3:::{BUCKET}",
    }
    stale_ours = {**bootstrap_s3.desired_policy_statement(BUCKET), "Resource": f"arn:aws:s3:::{BUCKET}"}
    client.put_bucket_policy(
        Bucket=BUCKET, Policy=json.dumps({"Version": "2012-10-17", "Statement": [foreign_statement, stale_ours]})
    )
    foreign_rule = {
        "ID": "example-abort-uploads",
        "Status": "Enabled",
        "Filter": {"Prefix": "tmp/"},
        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
    }
    stale_rule = {**bootstrap_s3.desired_lifecycle_rule(365)}
    client.put_bucket_lifecycle_configuration(
        Bucket=BUCKET, LifecycleConfiguration={"Rules": [foreign_rule, stale_rule]}
    )
    client.put_bucket_tagging(Bucket=BUCKET, Tagging={"TagSet": [{"Key": "owner", "Value": "example-team"}]})

    result = bootstrap(load_project(write_project(tmp_path)))
    assert {"bucket_policy", "lifecycle", "tags"} <= set(result["changed"])
    assert result["diff"]["lifecycle"]["before"]["noncurrent_days"] == 365
    assert result["diff"]["lifecycle"]["after"]["noncurrent_days"] == 30

    policy = json.loads(client.get_bucket_policy(Bucket=BUCKET)["Policy"])
    sids = [s.get("Sid") for s in policy["Statement"]]
    assert sorted(sids) == sorted(["ExampleReadOnly", POLICY_SID])  # foreign kept, ours replaced not duplicated
    rules = {r["ID"]: r for r in client.get_bucket_lifecycle_configuration(Bucket=BUCKET)["Rules"]}
    assert set(rules) == {"example-abort-uploads", LIFECYCLE_RULE_ID}
    assert rules[LIFECYCLE_RULE_ID]["NoncurrentVersionExpiration"]["NoncurrentDays"] == 30
    tags = {t["Key"]: t["Value"] for t in client.get_bucket_tagging(Bucket=BUCKET)["TagSet"]}
    assert tags == {"owner": "example-team", "managed-by": "code-orca"}
    assert bootstrap(load_project(write_project(tmp_path)))["changed"] == []


def test_kms_encryption_converges_and_lands_in_backend_hcl(tmp_path):
    project = load_project(write_project(tmp_path, encryption=f"kms:{KMS_ARN}"))
    result = bootstrap(project)
    assert result["diff"]["encryption"]["after"] == {
        "algorithm": "aws:kms",
        "kms_key_id": KMS_ARN,
        "bucket_key_enabled": True,
    }
    rule = s3().get_bucket_encryption(Bucket=BUCKET)["ServerSideEncryptionConfiguration"]["Rules"][0]
    assert rule["ApplyServerSideEncryptionByDefault"] == {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": KMS_ARN}
    assert f'kms_key_id   = "{KMS_ARN}"' in (tmp_path / "terraform/app/backend.hcl").read_text()
    assert bootstrap(project)["changed"] == []


def test_backend_hcl_holds_backend_settings_and_no_credentials(tmp_path):
    project = load_project(write_project(tmp_path))
    bootstrap(project)
    text = (tmp_path / "terraform/app/backend.hcl").read_text()
    assert 'bucket       = "example-tfstate-123456789012"' in text
    assert 'key          = "example/app/terraform.tfstate"' in text
    assert 'region       = "us-east-1"' in text
    assert "use_lockfile = true" in text and "encrypt      = true" in text
    assert "kms_key_id" not in text and "dynamodb" not in text
    for forbidden in ("access_key", "secret_key", "token", "profile", "role_arn", "testing"):
        assert forbidden not in text.lower()
    assert oct((tmp_path / "terraform/app/backend.hcl").stat().st_mode & 0o777) == "0o644"


@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not on PATH")
def test_backend_hcl_is_valid_terraform_syntax(tmp_path):
    text = render_backend_hcl(
        {"bucket": "b", "key": "a/${x}/%{y}/terraform.tfstate", "region": "us-east-1", "use_lockfile": True}
    )
    path = tmp_path / "backend.tfvars"  # fmt only takes .tf/.tfvars; a backend file is the same attribute syntax
    path.write_text(text)
    proc = subprocess.run(
        ["terraform", "fmt", "-no-color", "-check", str(path)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "$${x}" in text and "%%{y}" in text  # template sequences escaped


def test_non_us_east_1_bucket_gets_a_location_constraint(tmp_path):
    project = load_project(write_project(tmp_path, region="eu-west-1"))
    bootstrap(project)
    assert s3("eu-west-1").get_bucket_location(Bucket=BUCKET)["LocationConstraint"] == "eu-west-1"
    assert bootstrap(project)["changed"] == []


def test_refuses_an_existing_bucket_in_another_region(tmp_path):
    s3("eu-west-1").create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
    with pytest.raises(BootstrapError) as e:
        bootstrap(load_project(write_project(tmp_path)))
    assert "eu-west-1" in str(e.value)


def test_refuses_a_local_backend_with_a_clear_message():
    with pytest.raises(BootstrapError) as e:
        bootstrap(load_project(REFERENCE))
    assert "local" in str(e.value) and "s3" in str(e.value)


def test_refuses_a_missing_stack_dir_before_touching_aws(tmp_path):
    path = write_project(tmp_path)
    shutil.rmtree(tmp_path / "terraform/app")
    with pytest.raises(BootstrapError) as e:
        bootstrap(load_project(path))
    assert "terraform/app" in str(e.value)
    assert s3().list_buckets()["Buckets"] == []


def test_never_touches_objects_and_clients_are_time_limited(tmp_path):
    rec = Recording()
    project = load_project(write_project(tmp_path))
    bootstrap(project, session_factory=rec, timeout_s=6)
    bootstrap(project, session_factory=rec, timeout_s=6)
    object_ops = [op for op in rec.ops if "Object" in op and "ObjectLock" not in op]
    assert object_ops == [] and "ListObjectsV2" not in rec.ops and "ListObjects" not in rec.ops
    assert {service for service, _ in rec.configs} == {"s3", "sts"}
    for _service, config in rec.configs:
        assert config.connect_timeout == 6 and config.read_timeout == 6
        assert config.retries["total_max_attempts"] == 3  # retries={"max_attempts": 2}


def test_a_hung_session_hits_the_deadline(tmp_path):
    import time

    def hung():
        time.sleep(5)

    start = time.monotonic()
    with pytest.raises(BootstrapError) as e:
        bootstrap(load_project(write_project(tmp_path)), session_factory=hung, timeout_s=0.05)
    assert time.monotonic() - start < 3 and "no answer within" in str(e.value)


def test_main_writes_the_output_file_contract(tmp_path, capsys):
    out = tmp_path / "output.json"
    rc = main(["--project", str(write_project(tmp_path)), "--output-file", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    assert {"bucket", "region", "account_id", "created", "changed", "dry_run", "backend_files"} <= set(doc)
    assert doc["created"] is True and doc["dry_run"] is False
    assert "changed:" in capsys.readouterr().out


def test_main_honours_codeorca_dry_run_and_output_file_env(tmp_path, monkeypatch):
    out = tmp_path / "output.json"
    monkeypatch.setenv("CODEORCA_DRY_RUN", "1")
    monkeypatch.setenv("CODEORCA_OUTPUT_FILE", str(out))
    assert main(["--project", str(write_project(tmp_path))]) == 0
    assert json.loads(out.read_text())["dry_run"] is True
    assert s3().list_buckets()["Buckets"] == []


def test_main_returns_2_with_the_reason_on_refusal(capsys):
    assert main(["--project", str(REFERENCE)]) == 2
    assert "local backend has nothing to bootstrap" in capsys.readouterr().err


def test_a_previous_backend_hcl_is_recorded_by_digest_never_by_content(tmp_path):
    """Review finding: the diff copied the previous backend.hcl's text, credentials included, into the helper's
    output (and from there result.json, outputs/ and run.json)."""
    cred = "FIXTURE-SECRET-old-backend-secret-key-0001"
    old = f'bucket     = "old"\naccess_key = "AKIAEXAMPLEEXAMPLE00"\nsecret_key = "{cred}"\n'
    hcl = tmp_path / "terraform/app/backend.hcl"
    project_file = write_project(tmp_path)
    hcl.write_text(old)
    out = tmp_path / "output.json"
    assert main(["--project", str(project_file), "--output-file", str(out)]) == 0
    text = out.read_text()
    assert cred not in text and "AKIAEXAMPLE" not in text
    doc = json.loads(text)
    entry = doc["diff"]["backend_file:app"]
    assert entry["before"] == {"sha256": hashlib.sha256(old.encode()).hexdigest(), "bytes": len(old.encode())}
    assert entry["after"] == hcl.read_text() and "secret_key" not in entry["after"]
    assert any("backend_file:app" in n and "credential-looking" in n for n in doc["notes"])
    assert doc["diff"]["backend_file:net"]["before"] is None  # a new file


class _SlowClients:
    """A session whose client creation hangs: what botocore does while a credential_process runs."""

    def client(self, *args, **kwargs):
        import time

        time.sleep(5)


class _NoCredentials(Exception):
    pass


class _FailingClients:
    def client(self, *args, **kwargs):
        raise _NoCredentials("credential_process said: FIXTURE-SECRET-provider-stderr-0001")


def test_a_hung_client_creation_hits_the_deadline(tmp_path):
    """Review finding: only the bare Session() ran under the deadline; client creation (where the credential
    chain resolves) did not."""
    import time

    start = time.monotonic()
    with pytest.raises(BootstrapError, match="no answer within"):
        bootstrap(load_project(write_project(tmp_path)), session_factory=_SlowClients, timeout_s=0.05)
    assert time.monotonic() - start < 3


def test_a_credential_error_at_client_creation_is_value_free(tmp_path):
    with pytest.raises(BootstrapError) as e:
        bootstrap(load_project(write_project(tmp_path)), session_factory=_FailingClients, timeout_s=1)
    assert "_NoCredentials" in str(e.value) and "FIXTURE-SECRET" not in str(e.value)


def test_a_hung_credential_process_hits_the_deadline(tmp_path, monkeypatch):
    """The real chain: a boto3 Session on a profile whose credential_process hangs (a locked aws-vault)."""
    import time

    config = tmp_path / "aws-config"
    config.write_text("[profile hung]\ncredential_process = /bin/sleep 5\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    start = time.monotonic()
    with pytest.raises(BootstrapError, match="no answer within"):
        bootstrap(
            load_project(write_project(tmp_path)),
            session_factory=lambda: boto3.Session(profile_name="hung"),
            timeout_s=0.1,
        )
    assert time.monotonic() - start < 3
