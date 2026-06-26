variable "name" {
  description = "Nombre/prefijo del Web ACL y sus métricas (ej: \"porkcolombia\")."
  type        = string
}

variable "scope" {
  description = "REGIONAL (ALB / API Gateway / AppSync) o CLOUDFRONT."
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["REGIONAL", "CLOUDFRONT"], var.scope)
    error_message = "scope debe ser REGIONAL o CLOUDFRONT."
  }
}

# Prende/apaga cualquier AWS Managed Rule Group con true/false.
# El default trae el catálogo de AWS que funciona con toggle simple (sin config
# obligatoria). Puedes agregar cualquier otro nombre AWSManagedRules... y se
# desplegará igual; los que están en false no se crean.
#
# NOTA: ATP / ACFP / Anti-DDoS requieren config obligatoria y se ignoran aquí
# aunque los pongas en true (Anti-DDoS tiene su propia variable `anti_ddos`).
variable "managed_rule_groups" {
  description = "Activa/desactiva cada AWS Managed Rule Group con true/false."
  type        = map(bool)
  default = {
    # Baseline
    AWSManagedRulesCommonRuleSet          = true
    AWSManagedRulesAdminProtectionRuleSet = false
    AWSManagedRulesKnownBadInputsRuleSet  = true
    # IP reputation
    AWSManagedRulesAmazonIpReputationList = true
    AWSManagedRulesAnonymousIpList        = true
    # Use-case específico
    AWSManagedRulesSQLiRuleSet      = true
    AWSManagedRulesLinuxRuleSet     = false
    AWSManagedRulesUnixRuleSet      = false # POSIX
    AWSManagedRulesWindowsRuleSet   = false
    AWSManagedRulesPHPRuleSet       = false
    AWSManagedRulesWordPressRuleSet = false
    # Bot Control (de pago)
    AWSManagedRulesBotControlRuleSet = false
  }
}

# Ajustes avanzados opcionales por managed rule group (key = nombre del grupo).
#   count_override : pone TODO el grupo en modo count (observar, no bloquear)
#   version        : fija una versión estática del grupo (ej: "Version_2.0")
#   excluded_rules : atajo — manda estas reglas a count (el caso más común).
#                    Ej. típico contra falso positivo de tamaño de URL en CommonRuleSet:
#                      excluded_rules = ["SizeRestrictions_URIPATH"]
#   rule_overrides : acción explícita por regla: allow|block|count|captcha|challenge.
#                    Úsalo cuando necesitas algo distinto de count.
#   scope_down     : aplica el grupo SOLO al tráfico que matchee (ej: solo /api/*).
#   (si una regla aparece en ambos, gana rule_overrides. Máx. 10 overrides por grupo en AWS.)
variable "managed_rule_group_overrides" {
  description = "Overrides opcionales por managed rule group."
  type = map(object({
    count_override = optional(bool, false)
    version        = optional(string)
    excluded_rules = optional(list(string), [])
    rule_overrides = optional(map(string), {})
    scope_down = optional(object({
      type                  = string # byte_match | regex_match | size_constraint
      field                 = string # uri_path | query_string | method | body | all_query_args | header
      header_name           = optional(string)
      search_string         = optional(string)
      regex_string          = optional(string)
      positional_constraint = optional(string, "STARTS_WITH")
      comparison_operator   = optional(string, "GT")
      size                  = optional(number)
      text_transformation   = optional(string, "NONE")
    }))
  }))
  default = {}

  validation {
    condition = alltrue(flatten([
      for g in values(var.managed_rule_group_overrides) : [
        for action in values(g.rule_overrides) :
        contains(["allow", "block", "count", "captcha", "challenge"], action)
      ]
    ]))
    error_message = "rule_overrides: la acción debe ser allow, block, count, captcha o challenge."
  }
}

# Anti-DDoS managed rule group (de pago, intelligent threat mitigation).
# null = desactivado. Requiere config obligatoria (challenge + sensibilidad).
variable "anti_ddos" {
  description = "Config del Anti-DDoS managed rule group. null = desactivado."
  type = object({
    sensitivity_to_block  = optional(string, "LOW")    # LOW | MEDIUM | HIGH (block)
    challenge_enabled     = optional(bool, true)       # activa el silent challenge
    challenge_sensitivity = optional(string, "HIGH")   # LOW | MEDIUM | HIGH
    exempt_uri_regexes    = optional(list(string), []) # URIs exentas del challenge
    count_override        = optional(bool, false)      # observar sin actuar
  })
  default = null

  validation {
    condition = var.anti_ddos == null ? true : (
      contains(["LOW", "MEDIUM", "HIGH"], var.anti_ddos.sensitivity_to_block) &&
      contains(["LOW", "MEDIUM", "HIGH"], var.anti_ddos.challenge_sensitivity)
    )
    error_message = "anti_ddos: sensitivity_to_block y challenge_sensitivity deben ser LOW, MEDIUM o HIGH."
  }
}

# Listas de IPs a PERMITIR (bypass del WAF). Soporta IPv4 e IPv6 (se autodetecta).
# Una IP permitida termina la evaluación y se salta TODAS las demás reglas.
variable "ip_allow_list" {
  description = "CIDRs a permitir (allow terminante). [] = ninguno."
  type        = list(string)
  default     = []
}

# Listas de IPs a BLOQUEAR. Soporta IPv4 e IPv6 (se autodetecta).
variable "ip_block_list" {
  description = "CIDRs a bloquear. [] = ninguno."
  type        = list(string)
  default     = []
}

# Reglas de rate limit. La key es el nombre de la regla. {} = ninguna.
variable "rate_limit_rules" {
  description = "Rate limits configurables (req / 5 min por IP). La key es el nombre."
  type = map(object({
    limit       = number                    # ej: 5000
    action      = optional(string, "block") # block | count
    path_prefix = optional(string)          # opcional: limitar solo a cierto path
  }))
  default = {}

  validation {
    condition     = alltrue([for r in values(var.rate_limit_rules) : contains(["block", "count"], r.action)])
    error_message = "rate_limit_rules: action debe ser block o count."
  }
}

# Bloqueo por geo-referencia. [] = desactivado.
variable "geo_block_countries" {
  description = "Códigos ISO-3166 alpha-2 a bloquear (ej: [\"CN\", \"RU\"]). [] = ninguno."
  type        = list(string)
  default     = []
}

# Reglas custom de UN statement. La key es el nombre. {} = ninguna.
#   priority : orden relativo entre custom rules (la prioridad absoluta la asigna el módulo)
#   action   : allow | block | count
#   type     : byte_match | regex_match | size_constraint
#   field    : uri_path | query_string | method | body | all_query_args | header
# Para lógica compleja (AND/OR/NOT), usa custom_rule_group_arns.
variable "custom_rules" {
  description = "Reglas custom simples (un statement)."
  type = map(object({
    priority              = number
    action                = string
    type                  = string
    field                 = string
    header_name           = optional(string)             # si field = header
    search_string         = optional(string)             # byte_match
    regex_string          = optional(string)             # regex_match
    positional_constraint = optional(string, "CONTAINS") # byte_match: EXACTLY|STARTS_WITH|ENDS_WITH|CONTAINS|CONTAINS_WORD
    comparison_operator   = optional(string, "GT")       # size_constraint: EQ|NE|LE|LT|GE|GT
    size                  = optional(number)             # size_constraint (bytes)
    text_transformation   = optional(string, "NONE")     # NONE|LOWERCASE|URL_DECODE|COMPRESS_WHITE_SPACE|...
  }))
  default = {}

  validation {
    condition     = alltrue([for r in values(var.custom_rules) : contains(["allow", "block", "count"], r.action)])
    error_message = "custom_rules: action debe ser allow, block o count."
  }

  validation {
    condition     = alltrue([for r in values(var.custom_rules) : contains(["byte_match", "regex_match", "size_constraint"], r.type)])
    error_message = "custom_rules: type debe ser byte_match, regex_match o size_constraint."
  }
}

# Escape hatch: rule groups propios (aws_wafv2_rule_group) para lógica arbitraria.
# El cliente los define en su repo y pasa { arn, priority }. La key es el nombre.
variable "custom_rule_group_arns" {
  description = "Rule groups propios a referenciar (lógica compleja)."
  type = map(object({
    arn      = string
    priority = number
  }))
  default = {}
}

# Logging del WAF. null = desactivado.
#   log_destination_arns : ARNs de CloudWatch Log Group / Firehose / S3.
#                          El recurso destino DEBE llamarse aws-waf-logs-* (regla de AWS).
#   redact_fields        : campos a ocultar en los logs (ej: el header authorization).
#   log_only_actions     : si se setea, SOLO loguea esas acciones; [] = loguea todo.
variable "logging" {
  description = "Config de logging del WAF (CloudWatch/Firehose/S3)."
  type = object({
    log_destination_arns = list(string)
    redact_fields = optional(list(object({
      type = string           # method | query_string | uri_path | single_header
      name = optional(string) # requerido si type = single_header (en minúscula)
    })), [])
    log_only_actions = optional(list(string), []) # ALLOW|BLOCK|COUNT|CAPTCHA|CHALLENGE|EXCLUDED_AS_COUNT
  })
  default = null

  validation {
    condition = var.logging == null ? true : alltrue([
      for f in var.logging.redact_fields : contains(["method", "query_string", "uri_path", "single_header"], f.type)
    ])
    error_message = "logging.redact_fields: type debe ser method, query_string, uri_path o single_header."
  }
}

# ARNs de ALB / API Gateway a asociar (solo REGIONAL).
# En CLOUDFRONT se conecta con web_acl_id en la distribución (ver outputs).
variable "associate_resource_arns" {
  description = "ARNs de recursos REGIONAL (ALB/API GW) a asociar al Web ACL."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags a aplicar al Web ACL."
  type        = map(string)
  default     = {}
}
