# Provider-free reference stack: runs offline, exercises a sensitive variable, outputs, and a
# computed value that echoes a secret (the case Terraform's own sensitivity flags do not cover).
terraform {
  required_version = ">= 1.10"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "app_secret" {
  type      = string
  sensitive = true
  # No default on purpose: a sensitive variable's default re-enters plan JSON in clear text.
}

locals {
  app_name = "example-app-${var.environment}"
  app_host = "127.0.0.1"
}

resource "terraform_data" "app" {
  input = {
    name   = local.app_name
    secret = var.app_secret
  }
  triggers_replace = [var.environment]
}

resource "terraform_data" "app_secret" {
  input = var.app_secret
}

output "app_host" {
  value = local.app_host
}

output "app_fqdn" {
  value = "app-${var.environment}.example.com"
}

output "app_bucket" {
  value = "example-app-123456789012"
}

output "app_token" {
  value     = var.app_secret
  sensitive = true
}
