"""State-backend bootstrap (plan section 5.11): create and converge the remote backend before the first init.

v1 has one backend: S3 with Terraform >= 1.10's S3-native ``use_lockfile`` (no DynamoDB table),
:mod:`codeorca.bootstrap.s3`, runnable as ``python -m codeorca.bootstrap.s3 --project codeorca.yaml``.
"""
