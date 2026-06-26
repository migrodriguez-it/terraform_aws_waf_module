locals {
  # WAF names y metric names solo permiten [A-Za-z0-9_-]. Saneamos var.name por si
  # prefix/client_name traen espacios, puntos, barras u otros caracteres no válidos.
  safe_name = replace(var.name, "/[^A-Za-z0-9_-]/", "-")

  # Grupos que NO se pueden desplegar con statement "pelado" (requieren config).
  # Se excluyen del toggle genérico aunque vengan en true.
  config_required = [
    "AWSManagedRulesAntiDDoSRuleSet", # usa la variable anti_ddos
    "AWSManagedRulesATPRuleSet",
    "AWSManagedRulesACFPRuleSet",
  ]

  # Orden canónico de evaluación de los grupos conocidos (menor prioridad = primero).
  managed_rule_order = [
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesAdminProtectionRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesLinuxRuleSet",
    "AWSManagedRulesUnixRuleSet",
    "AWSManagedRulesWindowsRuleSet",
    "AWSManagedRulesPHPRuleSet",
    "AWSManagedRulesWordPressRuleSet",
    "AWSManagedRulesBotControlRuleSet",
  ]

  # Todos los grupos activados (true), excluyendo los que requieren config.
  enabled_all = [for k, v in var.managed_rule_groups : k if v && !contains(local.config_required, k)]

  # Conocidos en orden canónico + cualquier grupo extra (alfabético) al final.
  enabled_known   = [for r in local.managed_rule_order : r if contains(local.enabled_all, r)]
  enabled_unknown = sort([for r in local.enabled_all : r if !contains(local.managed_rule_order, r)])
  enabled_managed = concat(local.enabled_known, local.enabled_unknown)

  # Combina excluded_rules (→ count) con rule_overrides (acción explícita gana) por grupo.
  mrg_overrides = {
    for name, cfg in var.managed_rule_group_overrides :
    name => merge(
      { for r in cfg.excluded_rules : r => "count" },
      cfg.rule_overrides
    )
  }

  # IP sets: se separan por familia (un ip_set no puede mezclar IPv4 e IPv6).
  allow_v4 = [for c in var.ip_allow_list : c if !strcontains(c, ":")]
  allow_v6 = [for c in var.ip_allow_list : c if strcontains(c, ":")]
  block_v4 = [for c in var.ip_block_list : c if !strcontains(c, ":")]
  block_v6 = [for c in var.ip_block_list : c if strcontains(c, ":")]

  # Reglas de IP (prioridades 0..3): allow primero (terminante), luego block.
  ip_rules = concat(
    length(local.allow_v4) > 0 ? [{ name = "allow-ip-v4", priority = 0, action = "allow", arn = aws_wafv2_ip_set.allow_v4[0].arn }] : [],
    length(local.allow_v6) > 0 ? [{ name = "allow-ip-v6", priority = 1, action = "allow", arn = aws_wafv2_ip_set.allow_v6[0].arn }] : [],
    length(local.block_v4) > 0 ? [{ name = "block-ip-v4", priority = 2, action = "block", arn = aws_wafv2_ip_set.block_v4[0].arn }] : [],
    length(local.block_v6) > 0 ? [{ name = "block-ip-v6", priority = 3, action = "block", arn = aws_wafv2_ip_set.block_v6[0].arn }] : [],
  )

  # Custom rules: orden relativo por el campo priority → banda 30+.
  custom_order      = [for s in sort([for k, v in var.custom_rules : format("%05d|%s", v.priority, k)]) : split("|", s)[1]]
  custom_priorities = { for idx, k in local.custom_order : k => 30 + idx }

  # Rule group refs (escape hatch): banda 70+.
  rgref_order      = [for s in sort([for k, v in var.custom_rule_group_arns : format("%05d|%s", v.priority, k)]) : split("|", s)[1]]
  rgref_priorities = { for idx, k in local.rgref_order : k => 70 + idx }

  # Prioridades de rate limits: 100+ (no chocan con el resto).
  rate_priorities = { for idx, k in sort(keys(var.rate_limit_rules)) : k => 100 + idx }
}

#################################################
# IP sets (allow / block, por familia)
#################################################
resource "aws_wafv2_ip_set" "allow_v4" {
  count              = length(local.allow_v4) > 0 ? 1 : 0
  name               = "${local.safe_name}-allow-v4"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = local.allow_v4
  tags               = var.tags
}

resource "aws_wafv2_ip_set" "allow_v6" {
  count              = length(local.allow_v6) > 0 ? 1 : 0
  name               = "${local.safe_name}-allow-v6"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = local.allow_v6
  tags               = var.tags
}

resource "aws_wafv2_ip_set" "block_v4" {
  count              = length(local.block_v4) > 0 ? 1 : 0
  name               = "${local.safe_name}-block-v4"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = local.block_v4
  tags               = var.tags
}

resource "aws_wafv2_ip_set" "block_v6" {
  count              = length(local.block_v6) > 0 ? 1 : 0
  name               = "${local.safe_name}-block-v6"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = local.block_v6
  tags               = var.tags
}

resource "aws_wafv2_web_acl" "this" {
  name        = "${local.safe_name}-waf"
  description = "Web ACL gestionado por Terraform - ${var.scope}"
  scope       = var.scope

  default_action {
    allow {}
  }

  #################################################
  # IP allow / block (prioridades 0..3)
  #################################################
  dynamic "rule" {
    for_each = local.ip_rules
    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
      }

      statement {
        ip_set_reference_statement {
          arn = rule.value.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  #################################################
  # Bloqueo por geo-referencia (prioridad 5)
  #################################################
  dynamic "rule" {
    for_each = length(var.geo_block_countries) > 0 ? [1] : []
    content {
      name     = "geo-block"
      priority = 5

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.geo_block_countries
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "GeoBlock"
        sampled_requests_enabled   = true
      }
    }
  }

  #################################################
  # Anti-DDoS managed rule group (prioridad 8)
  #################################################
  dynamic "rule" {
    for_each = var.anti_ddos == null ? [] : [var.anti_ddos]
    content {
      name     = "AntiDDoS"
      priority = 8

      override_action {
        dynamic "count" {
          for_each = rule.value.count_override ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = rule.value.count_override ? [] : [1]
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = "AWSManagedRulesAntiDDoSRuleSet"

          managed_rule_group_configs {
            aws_managed_rules_anti_ddos_rule_set {
              sensitivity_to_block = rule.value.sensitivity_to_block

              client_side_action_config {
                challenge {
                  usage_of_action = rule.value.challenge_enabled ? "ENABLED" : "DISABLED"
                  sensitivity     = rule.value.challenge_sensitivity

                  dynamic "exempt_uri_regular_expression" {
                    for_each = rule.value.exempt_uri_regexes
                    content {
                      regex_string = exempt_uri_regular_expression.value
                    }
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "AntiDDoS"
        sampled_requests_enabled   = true
      }
    }
  }

  #################################################
  # Managed rule groups (true / false + overrides) — prioridad 10+
  #################################################
  dynamic "rule" {
    for_each = local.enabled_managed
    content {
      name     = rule.value
      priority = 10 + rule.key

      # none = usa la acción del grupo (block). count = solo observa.
      override_action {
        dynamic "count" {
          for_each = try(var.managed_rule_group_overrides[rule.value].count_override, false) ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = try(var.managed_rule_group_overrides[rule.value].count_override, false) ? [] : [1]
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.value
          version     = try(var.managed_rule_group_overrides[rule.value].version, null)

          # Override de acción por regla individual (excluded_rules + rule_overrides).
          dynamic "rule_action_override" {
            for_each = try(local.mrg_overrides[rule.value], {})
            content {
              name = rule_action_override.key
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }

          # Scope-down: aplica el grupo SOLO a requests que matcheen (ej: solo /api/*).
          dynamic "scope_down_statement" {
            for_each = try(var.managed_rule_group_overrides[rule.value].scope_down, null) == null ? [] : [var.managed_rule_group_overrides[rule.value].scope_down]
            content {
              dynamic "byte_match_statement" {
                for_each = scope_down_statement.value.type == "byte_match" ? [1] : []
                content {
                  search_string         = scope_down_statement.value.search_string
                  positional_constraint = scope_down_statement.value.positional_constraint

                  field_to_match {
                    dynamic "uri_path" {
                      for_each = scope_down_statement.value.field == "uri_path" ? [1] : []
                      content {}
                    }
                    dynamic "query_string" {
                      for_each = scope_down_statement.value.field == "query_string" ? [1] : []
                      content {}
                    }
                    dynamic "method" {
                      for_each = scope_down_statement.value.field == "method" ? [1] : []
                      content {}
                    }
                    dynamic "body" {
                      for_each = scope_down_statement.value.field == "body" ? [1] : []
                      content {}
                    }
                    dynamic "all_query_arguments" {
                      for_each = scope_down_statement.value.field == "all_query_args" ? [1] : []
                      content {}
                    }
                    dynamic "single_header" {
                      for_each = scope_down_statement.value.field == "header" ? [1] : []
                      content {
                        name = scope_down_statement.value.header_name
                      }
                    }
                  }

                  text_transformation {
                    priority = 0
                    type     = scope_down_statement.value.text_transformation
                  }
                }
              }

              dynamic "regex_match_statement" {
                for_each = scope_down_statement.value.type == "regex_match" ? [1] : []
                content {
                  regex_string = scope_down_statement.value.regex_string

                  field_to_match {
                    dynamic "uri_path" {
                      for_each = scope_down_statement.value.field == "uri_path" ? [1] : []
                      content {}
                    }
                    dynamic "query_string" {
                      for_each = scope_down_statement.value.field == "query_string" ? [1] : []
                      content {}
                    }
                    dynamic "method" {
                      for_each = scope_down_statement.value.field == "method" ? [1] : []
                      content {}
                    }
                    dynamic "body" {
                      for_each = scope_down_statement.value.field == "body" ? [1] : []
                      content {}
                    }
                    dynamic "all_query_arguments" {
                      for_each = scope_down_statement.value.field == "all_query_args" ? [1] : []
                      content {}
                    }
                    dynamic "single_header" {
                      for_each = scope_down_statement.value.field == "header" ? [1] : []
                      content {
                        name = scope_down_statement.value.header_name
                      }
                    }
                  }

                  text_transformation {
                    priority = 0
                    type     = scope_down_statement.value.text_transformation
                  }
                }
              }

              dynamic "size_constraint_statement" {
                for_each = scope_down_statement.value.type == "size_constraint" ? [1] : []
                content {
                  comparison_operator = scope_down_statement.value.comparison_operator
                  size                = scope_down_statement.value.size

                  field_to_match {
                    dynamic "uri_path" {
                      for_each = scope_down_statement.value.field == "uri_path" ? [1] : []
                      content {}
                    }
                    dynamic "query_string" {
                      for_each = scope_down_statement.value.field == "query_string" ? [1] : []
                      content {}
                    }
                    dynamic "method" {
                      for_each = scope_down_statement.value.field == "method" ? [1] : []
                      content {}
                    }
                    dynamic "body" {
                      for_each = scope_down_statement.value.field == "body" ? [1] : []
                      content {}
                    }
                    dynamic "all_query_arguments" {
                      for_each = scope_down_statement.value.field == "all_query_args" ? [1] : []
                      content {}
                    }
                    dynamic "single_header" {
                      for_each = scope_down_statement.value.field == "header" ? [1] : []
                      content {
                        name = scope_down_statement.value.header_name
                      }
                    }
                  }

                  text_transformation {
                    priority = 0
                    type     = scope_down_statement.value.text_transformation
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = replace(rule.value, "AWSManagedRules", "")
        sampled_requests_enabled   = true
      }
    }
  }

  #################################################
  # Reglas custom simples (un statement) — prioridad 30+
  #################################################
  dynamic "rule" {
    for_each = var.custom_rules
    content {
      name     = rule.key
      priority = local.custom_priorities[rule.key]

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "byte_match_statement" {
          for_each = rule.value.type == "byte_match" ? [1] : []
          content {
            search_string         = rule.value.search_string
            positional_constraint = rule.value.positional_constraint

            field_to_match {
              dynamic "uri_path" {
                for_each = rule.value.field == "uri_path" ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = rule.value.field == "query_string" ? [1] : []
                content {}
              }
              dynamic "method" {
                for_each = rule.value.field == "method" ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = rule.value.field == "body" ? [1] : []
                content {}
              }
              dynamic "all_query_arguments" {
                for_each = rule.value.field == "all_query_args" ? [1] : []
                content {}
              }
              dynamic "single_header" {
                for_each = rule.value.field == "header" ? [1] : []
                content {
                  name = rule.value.header_name
                }
              }
            }

            text_transformation {
              priority = 0
              type     = rule.value.text_transformation
            }
          }
        }

        dynamic "regex_match_statement" {
          for_each = rule.value.type == "regex_match" ? [1] : []
          content {
            regex_string = rule.value.regex_string

            field_to_match {
              dynamic "uri_path" {
                for_each = rule.value.field == "uri_path" ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = rule.value.field == "query_string" ? [1] : []
                content {}
              }
              dynamic "method" {
                for_each = rule.value.field == "method" ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = rule.value.field == "body" ? [1] : []
                content {}
              }
              dynamic "all_query_arguments" {
                for_each = rule.value.field == "all_query_args" ? [1] : []
                content {}
              }
              dynamic "single_header" {
                for_each = rule.value.field == "header" ? [1] : []
                content {
                  name = rule.value.header_name
                }
              }
            }

            text_transformation {
              priority = 0
              type     = rule.value.text_transformation
            }
          }
        }

        dynamic "size_constraint_statement" {
          for_each = rule.value.type == "size_constraint" ? [1] : []
          content {
            comparison_operator = rule.value.comparison_operator
            size                = rule.value.size

            field_to_match {
              dynamic "uri_path" {
                for_each = rule.value.field == "uri_path" ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = rule.value.field == "query_string" ? [1] : []
                content {}
              }
              dynamic "method" {
                for_each = rule.value.field == "method" ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = rule.value.field == "body" ? [1] : []
                content {}
              }
              dynamic "all_query_arguments" {
                for_each = rule.value.field == "all_query_args" ? [1] : []
                content {}
              }
              dynamic "single_header" {
                for_each = rule.value.field == "header" ? [1] : []
                content {
                  name = rule.value.header_name
                }
              }
            }

            text_transformation {
              priority = 0
              type     = rule.value.text_transformation
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "custom-${rule.key}"
        sampled_requests_enabled   = true
      }
    }
  }

  #################################################
  # Rule groups propios (escape hatch) — prioridad 70+
  #################################################
  dynamic "rule" {
    for_each = var.custom_rule_group_arns
    content {
      name     = rule.key
      priority = local.rgref_priorities[rule.key]

      override_action {
        none {}
      }

      statement {
        rule_group_reference_statement {
          arn = rule.value.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "rgref-${rule.key}"
        sampled_requests_enabled   = true
      }
    }
  }

  #################################################
  # Rate limits (una regla por entrada del map) — prioridad 100+
  #################################################
  dynamic "rule" {
    for_each = var.rate_limit_rules
    content {
      name     = rule.key
      priority = local.rate_priorities[rule.key]

      action {
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        rate_based_statement {
          limit              = rule.value.limit
          aggregate_key_type = "IP"

          # Si se pasa path_prefix, el rate limit solo aplica a ese path.
          dynamic "scope_down_statement" {
            for_each = rule.value.path_prefix == null ? [] : [1]
            content {
              byte_match_statement {
                positional_constraint = "STARTS_WITH"
                search_string         = rule.value.path_prefix

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "rate-${rule.key}"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.safe_name}-webacl"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

#################################################
# Asociación a ALB / API Gateway (solo REGIONAL)
#################################################
resource "aws_wafv2_web_acl_association" "this" {
  for_each     = var.scope == "REGIONAL" ? toset(var.associate_resource_arns) : toset([])
  resource_arn = each.value
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

#################################################
# Logging (CloudWatch / Firehose / S3)
#################################################
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count                   = var.logging == null ? 0 : 1
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = var.logging.log_destination_arns

  # Campos a ocultar en los logs.
  dynamic "redacted_fields" {
    for_each = var.logging.redact_fields
    content {
      dynamic "method" {
        for_each = redacted_fields.value.type == "method" ? [1] : []
        content {}
      }
      dynamic "query_string" {
        for_each = redacted_fields.value.type == "query_string" ? [1] : []
        content {}
      }
      dynamic "uri_path" {
        for_each = redacted_fields.value.type == "uri_path" ? [1] : []
        content {}
      }
      dynamic "single_header" {
        for_each = redacted_fields.value.type == "single_header" ? [1] : []
        content {
          name = redacted_fields.value.name
        }
      }
    }
  }

  # Si se especifican acciones, solo se loguean esas (el resto se descarta).
  dynamic "logging_filter" {
    for_each = length(var.logging.log_only_actions) > 0 ? [1] : []
    content {
      default_behavior = "DROP"
      filter {
        behavior    = "KEEP"
        requirement = "MEETS_ANY"
        dynamic "condition" {
          for_each = var.logging.log_only_actions
          content {
            action_condition {
              action = condition.value
            }
          }
        }
      }
    }
  }
}