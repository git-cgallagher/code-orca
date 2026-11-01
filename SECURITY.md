# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub:
[Report a vulnerability](https://github.com/git-cgallagher/code-orca/security/advisories/new)
(the **Security** tab, then **Report a vulnerability**). Don't open a public issue for a security problem.

You can expect an acknowledgement within a week. This is a one-person project, so fixes are best effort.

## Supported versions

Only the latest release gets fixes.

## Scope

code-orca runs Terraform and Ansible with whatever credentials the operator hands to it and writes
redacted specifications of the resulting configuration. In scope: anything that lets a secret reach a
spec, a log, a run artifact or git; anything that lets a workflow file widen the Terraform deny floor
(destroy, state surgery, `-target`, `-auto-approve`, an unreviewed apply); a gate that can be passed
without a human on a terminal; and the container image or build pipeline. Vulnerabilities in
Terraform, ansible-core, collections or Python packages belong with their upstream projects; tell us
anyway if a fixed version exists and the image does not use it yet.
