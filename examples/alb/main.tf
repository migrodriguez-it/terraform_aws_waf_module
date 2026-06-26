provider "aws" {
  region = "us-east-1"
}

variable "alb_arn" {
  description = "ARN del ALB del cliente al que se asocia el WAF."
  type        = string
}

variable "log_group_arn" {
  description = "ARN del CloudWatch Log Group (debe llamarse aws-waf-logs-*)."
  type        = string
}

module "waf" {
  source = "../../modules/waf"

  name  = "{$locals.prefix}-waf"
  scope = "REGIONAL"

  # Prende/apaga cualquier grupo del catálogo de AWS con true/false.
  managed_rule_groups = {
    AWSManagedRulesCommonRuleSet          = true
    AWSManagedRulesAdminProtectionRuleSet = true
    AWSManagedRulesKnownBadInputsRuleSet  = true
    AWSManagedRulesSQLiRuleSet            = true
    AWSManagedRulesLinuxRuleSet           = true
    AWSManagedRulesUnixRuleSet            = true
    AWSManagedRulesAmazonIpReputationList = true
    AWSManagedRulesAnonymousIpList        = true
    AWSManagedRulesWindowsRuleSet         = false
    AWSManagedRulesPHPRuleSet             = false
    AWSManagedRulesWordPressRuleSet       = false
    AWSManagedRulesBotControlRuleSet      = false
  }

  # Overrides opcionales por grupo
  managed_rule_group_overrides = {
    AWSManagedRulesCommonRuleSet = {
      rule_overrides = {
        # Falso positivo típico: URL/query larga → manda esas reglas a count,
        # el resto de la CommonRuleSet sigue bloqueando.
        "SizeRestrictions_URIPATH"     = "count"
        "SizeRestrictions_QUERYSTRING" = "count"
      }
    }
    AWSManagedRulesSQLiRuleSet = {
      excluded_rules = ["SQLi_BODY"] # atajo simple → count
      # Aplica SQLi solo al tráfico de la API
      scope_down = {
        type                  = "byte_match"
        field                 = "uri_path"
        search_string         = "/api/"
        positional_constraint = "STARTS_WITH"
      }
    }
  }

  # ¿Quieres un límite de tamaño de URL propio (en vez del 1024 fijo de AWS)?
  # 1) manda SizeRestrictions_URIPATH a count (arriba)  2) define tu propio límite:
  # custom_rules = {
  #   uri-too-long = {
  #     priority = 1, action = "block", type = "size_constraint",
  #     field = "uri_path", comparison_operator = "GT", size = 2048
  #   }
  # }

  # Anti-DDoS (de pago) — silent challenge + bloqueo por sensibilidad
  anti_ddos = {
    sensitivity_to_block  = "LOW"
    challenge_enabled     = true
    challenge_sensitivity = "HIGH"
    exempt_uri_regexes    = ["^/health$"]
  }

  # IP allow (bypass total) / block — soporta IPv4 e IPv6
  ip_allow_list = ["203.0.113.10/32"]
  ip_block_list = ["198.51.100.0/24"]

  # Rate limit configurable (le dices el rate)
  rate_limit_rules = {
    global = { limit = 5000 }
    login  = { limit = 100, path_prefix = "/login", action = "block" }
  }

  # Geo-block (vacío = desactivado)
  geo_block_countries = []

  # Reglas custom (un statement)
  custom_rules = {
    block-admin-path = {
      priority              = 1
      action                = "block"
      type                  = "byte_match"
      field                 = "uri_path"
      search_string         = "/wp-admin"
      positional_constraint = "STARTS_WITH"
    }
  }

  # Logging → CloudWatch (el log group debe llamarse aws-waf-logs-*).
  # Loguea solo lo bloqueado y oculta el header authorization.
  logging = {
    log_destination_arns = [var.log_group_arn]
    redact_fields        = [{ type = "single_header", name = "authorization" }]
    log_only_actions     = ["BLOCK"]
  }

  # Se asocia al ALB del cliente
  associate_resource_arns = [var.alb_arn]

  tags = {
    Project = "porkcolombia"
    Managed = "terraform"
  }
}
