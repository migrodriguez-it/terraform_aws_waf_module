terraform {
  required_version = ">= 1.3"

  # Config parcial: el pipeline la completa con -backend-config (ver azure-pipelines.yml).
  backend "azurerm" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80"
    }
  }
}

provider "aws" {
  region = var.aws_region
  # Sin credenciales en código: el pipeline hace assume-role-with-web-identity (OIDC)
  # y exporta AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN al entorno.
  # Para scope = CLOUDFRONT, usa region = "us-east-1".
}

locals {
  # Nombre derivado de las variables que YA tienes en tu repo.
  waf_name = "${var.prefix}-${var.client_name}"
}

module "waf" {
  source = "../../modules/waf"

  name  = local.waf_name
  scope = var.scope

  # Cada input es null por defecto → el módulo usa SU propio default.
  # El pipeline (TF_VAR_* o -var-file por cliente) solo sobreescribe lo que cambie.
  managed_rule_groups          = var.managed_rule_groups
  managed_rule_group_overrides = var.managed_rule_group_overrides
  anti_ddos                    = var.anti_ddos
  ip_allow_list                = var.ip_allow_list
  ip_block_list                = var.ip_block_list
  rate_limit_rules             = var.rate_limit_rules
  geo_block_countries          = var.geo_block_countries
  custom_rules                 = var.custom_rules
  custom_rule_group_arns       = var.custom_rule_group_arns
  logging                      = var.logging
  associate_resource_arns      = var.associate_resource_arns

  tags = {
    Client    = var.client_name
    AccountId = var.account_id
    ManagedBy = "terraform"
  }
}

output "web_acl_arn" {
  value = module.waf.web_acl_arn
}
