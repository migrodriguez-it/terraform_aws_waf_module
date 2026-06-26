# --- Variables que YA tienes en tu repo (las referencia el pipeline / tu root) ---
variable "prefix" {
  description = "Prefijo estándar de tu organización."
  type        = string
}

variable "client_name" {
  description = "Nombre del cliente."
  type        = string
}

variable "account_id" {
  description = "AWS Account ID destino."
  type        = string
}

variable "aws_region" {
  description = "Región de AWS. Para scope CLOUDFRONT debe ser us-east-1."
  type        = string
  default     = "us-east-1"
}

# --- Inputs del WAF (todos opcionales: null/[] → el módulo usa sus defaults) ---
variable "scope" {
  type    = string
  default = "REGIONAL"
}

variable "managed_rule_groups" {
  type    = map(bool)
  default = null
}

variable "managed_rule_group_overrides" {
  type    = any
  default = null
}

variable "anti_ddos" {
  type    = any
  default = null
}

variable "ip_allow_list" {
  type    = list(string)
  default = []
}

variable "ip_block_list" {
  type    = list(string)
  default = []
}

variable "rate_limit_rules" {
  type    = any
  default = null
}

variable "geo_block_countries" {
  type    = list(string)
  default = []
}

variable "custom_rules" {
  type    = any
  default = null
}

variable "custom_rule_group_arns" {
  type    = any
  default = null
}

variable "logging" {
  type    = any
  default = null
}

variable "associate_resource_arns" {
  type    = list(string)
  default = []
}
