output "web_acl_arn" {
  description = "ARN del Web ACL. Úsalo en web_acl_id de la distribución CloudFront."
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "ID del Web ACL."
  value       = aws_wafv2_web_acl.this.id
}

output "web_acl_name" {
  description = "Nombre del Web ACL."
  value       = aws_wafv2_web_acl.this.name
}
