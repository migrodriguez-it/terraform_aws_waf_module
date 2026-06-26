# terraform-aws-waf

Módulo reutilizable para desplegar un **AWS WAFv2 Web ACL** consistente delante de
ALB / API Gateway (`REGIONAL`) o CloudFront (`CLOUDFRONT`). Cada repo de cliente lo
consume con `source = "...//modules/waf?ref=vX.Y.Z"`, prende/apaga reglas con
`true/false` y lo engancha a sus propios recursos.

## Uso rápido (ALB)

```hcl
module "waf" {
  source = "git::https://github.com/tu-org/terraform-aws-waf.git//modules/waf?ref=v1.0.0"

  name  = "cliente"
  scope = "REGIONAL"

  managed_rule_groups = {
    AWSManagedRulesAmazonIpReputationList = true
    AWSManagedRulesCommonRuleSet          = true
    AWSManagedRulesKnownBadInputsRuleSet  = true
    AWSManagedRulesSQLiRuleSet            = true
    AWSManagedRulesBotControlRuleSet      = false
    AWSManagedRulesAnonymousIpList        = true
  }

  rate_limit_rules = {
    global = { limit = 5000 }
  }

  geo_block_countries     = ["CN", "RU"]
  associate_resource_arns = [aws_lb.this.arn]
}
```

## Uso con CloudFront

`scope = "CLOUDFRONT"` exige un provider en `us-east-1` y la asociación se hace con
`web_acl_id` en la distribución (no con `associate_resource_arns`):

```hcl
module "waf" {
  source   = "git::https://github.com/tu-org/terraform-aws-waf.git//modules/waf?ref=v1.0.0"
  name     = "cliente-edge"
  scope    = "CLOUDFRONT"
  providers = { aws = aws.use1 }
  # ...
}

resource "aws_cloudfront_distribution" "this" {
  web_acl_id = module.waf.web_acl_arn
}
```

> Un Web ACL es **REGIONAL o CLOUDFRONT**, nunca ambos. Para proteger un ALB **y** un
> CloudFront en el mismo repo, llama al módulo dos veces (un scope cada una).

## Inputs

| Nombre | Tipo | Default | Descripción |
|---|---|---|---|
| `name` | `string` | — | Prefijo del Web ACL y métricas. |
| `scope` | `string` | `"REGIONAL"` | `REGIONAL` o `CLOUDFRONT`. |
| `managed_rule_groups` | `map(bool)` | catálogo AWS (ver abajo) | Prende/apaga cada AWS Managed Rule Group. Acepta cualquier nombre `AWSManagedRules...`. |
| `managed_rule_group_overrides` | `map(object)` | `{}` | `{ count_override, version, rule_overrides }` por grupo. |
| `anti_ddos` | `object` | `null` | Anti-DDoS (de pago): `{ sensitivity_to_block, challenge_enabled, challenge_sensitivity, exempt_uri_regexes, count_override }`. |
| `ip_allow_list` | `list(string)` | `[]` | CIDRs a permitir (allow terminante). IPv4 e IPv6. |
| `ip_block_list` | `list(string)` | `[]` | CIDRs a bloquear. IPv4 e IPv6. |
| `rate_limit_rules` | `map(object)` | `{}` | `{ limit, action, path_prefix }` por regla. |
| `geo_block_countries` | `list(string)` | `[]` | Códigos ISO-3166 alpha-2 a bloquear. |
| `custom_rules` | `map(object)` | `{}` | Reglas custom de un statement. |
| `custom_rule_group_arns` | `map(object)` | `{}` | Rule groups propios `{ arn, priority }`. |
| `logging` | `object` | `null` | `{ log_destination_arns, redact_fields, log_only_actions }`. |
| `associate_resource_arns` | `list(string)` | `[]` | ARNs ALB/API GW a asociar (solo REGIONAL). |
| `tags` | `map(string)` | `{}` | Tags del Web ACL. |

## Outputs

| Nombre | Descripción |
|---|---|
| `web_acl_arn` | ARN del Web ACL (para `web_acl_id` de CloudFront). |
| `web_acl_id` | ID del Web ACL. |
| `web_acl_name` | Nombre del Web ACL. |

## Catálogo de AWS Managed Rule Groups soportados

El `map(bool)` acepta **cualquier** nombre `AWSManagedRules...`. El default trae el
catálogo que funciona con toggle simple (sin config obligatoria):

| Grupo (`AWSManagedRules...`) | Categoría | WCU | Default |
|---|---|---:|:---:|
| `CommonRuleSet` | Baseline | 700 | ✅ |
| `AdminProtectionRuleSet` | Baseline | 100 | ❌ |
| `KnownBadInputsRuleSet` | Baseline | 200 | ✅ |
| `AmazonIpReputationList` | IP reputation | 25 | ✅ |
| `AnonymousIpList` | IP reputation | 50 | ✅ |
| `SQLiRuleSet` | Use-case | 200 | ✅ |
| `LinuxRuleSet` | Use-case | 200 | ❌ |
| `UnixRuleSet` (POSIX) | Use-case | 100 | ❌ |
| `WindowsRuleSet` | Use-case | 200 | ❌ |
| `PHPRuleSet` | Use-case | 100 | ❌ |
| `WordPressRuleSet` | Use-case | 100 | ❌ |
| `BotControlRuleSet` | Bot (de pago) | 50 | ❌ |
| `AntiDDoSRuleSet` | DDoS (de pago) | 50 | vía `anti_ddos` |

> **No soportados por el toggle simple** (requieren `managed_rule_group_configs`
> obligatorio — login/registration path): `ATPRuleSet`, `ACFPRuleSet`. Son funciones de
> pago de *intelligent threat mitigation*; se añadirían con un bloque dedicado.
>
> **Anti-DDoS** sí está soportado, pero por su propia variable `anti_ddos` (lleva config
> obligatoria de challenge). No lo pongas en `managed_rule_groups` — ahí se ignora.

## Anti-DDoS (variable `anti_ddos`)

Grupo de pago. Manda silent browser challenges durante un evento de DDoS y bloquea según
sensibilidad. Requiere un provider AWS reciente (probado con v6.51).

```hcl
anti_ddos = {
  sensitivity_to_block  = "LOW"   # LOW | MEDIUM | HIGH
  challenge_enabled     = true
  challenge_sensitivity = "HIGH"
  exempt_uri_regexes    = ["^/health$"]  # URIs que no reciben challenge
}
```

## IP allow / block lists

Aceptan IPv4 e IPv6 mezclados (el módulo crea los `aws_wafv2_ip_set` por familia). El
**allow es terminante**: una IP en `ip_allow_list` se salta TODAS las demás reglas.

```hcl
ip_allow_list = ["203.0.113.10/32", "2001:db8::/32"]  # oficina/monitoreo: bypass total
ip_block_list = ["198.51.100.0/24"]                    # bloqueo directo
```

## Reglas custom

Dos niveles:

**1. `custom_rules`** — reglas de un solo statement (lo común). `type` =
`byte_match` | `regex_match` | `size_constraint`; `field` = `uri_path` |
`query_string` | `method` | `body` | `all_query_args` | `header`.

```hcl
custom_rules = {
  block-admin = {
    priority              = 1
    action                = "block"          # allow | block | count
    type                  = "byte_match"
    field                 = "uri_path"
    search_string         = "/wp-admin"
    positional_constraint = "STARTS_WITH"
  }
  block-big-body = {
    priority            = 2
    action              = "block"
    type                = "size_constraint"
    field               = "body"
    comparison_operator = "GT"
    size                = 1048576            # 1 MB
  }
}
```

**2. `custom_rule_group_arns`** (escape hatch) — para lógica compleja (AND/OR/NOT)
defines tu propio `aws_wafv2_rule_group` y pasas el ARN:

```hcl
custom_rule_group_arns = {
  reglas-app = { arn = aws_wafv2_rule_group.app.arn, priority = 1 }
}
```

## Logging

Referencia un destino **ya existente** (el módulo no lo crea). El recurso destino —
CloudWatch Log Group, Firehose o bucket S3 — **debe llamarse `aws-waf-logs-*`** (regla de
AWS). `log_only_actions` filtra qué se loguea; `redact_fields` oculta campos sensibles.

```hcl
logging = {
  log_destination_arns = [aws_cloudwatch_log_group.waf.arn]  # nombre aws-waf-logs-...
  redact_fields        = [{ type = "single_header", name = "authorization" }]
  log_only_actions     = ["BLOCK"]   # [] = loguear todo
}
```

## Prioridades de las reglas

- IP allow / block: `0..3` (allow primero, terminante).
- Geo-block: `5`.
- Anti-DDoS: `8`.
- Managed rule groups: `10..29` (conocidos en orden canónico; extras alfabéticos al final).
- Reglas custom (`custom_rules`): `30..69`.
- Rule group refs (`custom_rule_group_arns`): `70..99`.
- Rate limits: `100+`.

## Presupuesto de WCU (límite por defecto: 1500)

Suma el WCU de cada grupo activado (tabla de arriba). El default (~1175 WCU) cabe holgado.
Activar **todo** el catálogo supera los 1500 → pide aumento de WCU a AWS o reparte en
varios Web ACLs.

> **BotControl** es de pago (cargo mensual + por request). Por eso viene en `false`.

## Overrides de managed rule groups

Compatibilidad completa de overrides de AWS:

- **`count_override`** — todo el grupo a `count` (observar sin bloquear).
- **`version`** — fija una versión estática del grupo.
- **`excluded_rules`** — atajo para el caso común: manda esas reglas a `count`.
- **`rule_overrides`** — acción explícita por **regla individual**: `allow | block | count |
  captcha | challenge`. Úsalo cuando necesitas algo distinto de `count`.
- **`scope_down`** — aplica el grupo **solo** al tráfico que matchee (ej: CommonRuleSet
  solo en `/api/*`). `type` = `byte_match | regex_match | size_constraint`.

(`excluded_rules` y `rule_overrides` conviven; si una regla está en ambos, gana
`rule_overrides`. Límite de AWS: 10 overrides por grupo.)

```hcl
AWSManagedRulesSQLiRuleSet = {
  excluded_rules = ["SQLi_BODY"]
  scope_down = {
    type = "byte_match", field = "uri_path"
    search_string = "/api/", positional_constraint = "STARTS_WITH"
  }
}
```

> **Tamaño de URL configurable:** el umbral de `SizeRestrictions_URIPATH` (1024 bytes) lo
> fija AWS y no se cambia. Si quieres tu propio límite: manda esa regla a `count` y agrega
> un `custom_rules` tipo `size_constraint` sobre `uri_path` con el byte-límite que decidas.

```hcl
managed_rule_group_overrides = {
  AWSManagedRulesCommonRuleSet = {
    # Caso común (90%): solo apagar la regla problemática → count
    excluded_rules = ["SizeRestrictions_URIPATH", "SizeRestrictions_QUERYSTRING"]
    # Cuando necesitas otra acción:
    rule_overrides = { "NoUserAgent_HEADER" = "challenge" }
  }
  AWSManagedRulesSQLiRuleSet = { count_override = true }  # grupo entero en observación
}
```

> **Falsos positivos de tamaño** (CommonRuleSet): `SizeRestrictions_URIPATH` (URI > 1 KB),
> `SizeRestrictions_QUERYSTRING` (query > 2 KB), `SizeRestrictions_Cookie_HEADER`
> (cookies > 10 KB), `SizeRestrictions_BODY` (body > 8 KB). Mándalas a `count` para que
> dejen de bloquear sin desactivar el resto del grupo.
