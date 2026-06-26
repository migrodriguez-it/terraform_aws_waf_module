# Raíz para Azure DevOps (backend azurerm + OIDC a AWS)

Esta es la **configuración raíz** que ejecuta el pipeline. Llama a `../../modules/waf` y
mapea sus inputs a las variables que ya tienes en tu repo (`prefix`, `client_name`,
`account_id`). **No ejecutes Terraform dentro de `modules/waf`** — ese es un módulo hijo
y por eso te pedía `var.name` interactivamente.

## Cómo se ejecuta

Desde esta carpeta (`examples/azure-devops`), nunca desde el módulo:

```bash
terraform init -backend-config=... -backend-config=...
terraform plan  -var-file=clients/<cliente>.tfvars
terraform apply tfplan
```

El `azure-pipelines.yml` (en la raíz del repo) hace esto automáticamente.

## Variables

- **Identidad** (`prefix`, `client_name`, `account_id`): vienen del Variable Group como
  `TF_VAR_prefix`, etc. — las que ya manejas.
- **Config del WAF** (`managed_rule_groups`, `anti_ddos`, `rate_limit_rules`, …): por
  defecto son `null` → el módulo aplica sus propios defaults. Solo defines lo que cambie,
  en `clients/<cliente>.tfvars`.

## Backend (azurerm) — config parcial

El bloque `backend "azurerm" {}` se rellena en el pipeline con `-backend-config`:

| Clave | Origen |
|---|---|
| `resource_group_name` | `BACKEND_RG` |
| `storage_account_name` | `BACKEND_SA` |
| `container_name` | `BACKEND_CONTAINER` |
| `key` | `<cliente>.tfstate` |

El acceso al storage usa el token OIDC de Azure (`ARM_USE_OIDC=true`).

## Auth a AWS por OIDC

El pipeline usa el token OIDC de Azure DevOps para `assume-role-with-web-identity`. En AWS
necesitas un **IAM OIDC provider** que confíe en tu organización de Azure DevOps y un rol
con esta trust policy (ajusta `<...>`):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/vstoken.dev.azure.com/<ADO_ORG_GUID>"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "vstoken.dev.azure.com/<ADO_ORG_GUID>:aud": "api://AzureADTokenExchange",
        "vstoken.dev.azure.com/<ADO_ORG_GUID>:sub": "sc://<ORG>/<PROYECTO>/<SERVICE_CONNECTION>"
      }
    }
  }]
}
```

El `role-arn` que asume el pipeline va en el Variable Group como `AWS_ROLE_ARN`.
