# CLOUDFRONT exige que el Web ACL viva en us-east-1.
provider "aws" {
  alias  = "use1"
  region = "us-east-1"
}

module "waf" {
  source = "../../modules/waf"

  name  = "{$locals.prefix}-cf-waf"
  scope = "CLOUDFRONT"

  managed_rule_groups = {
    AWSManagedRulesAmazonIpReputationList = true
    AWSManagedRulesCommonRuleSet          = true
    AWSManagedRulesKnownBadInputsRuleSet  = true
    AWSManagedRulesAnonymousIpList        = true
  }

  rate_limit_rules = {
    global = { limit = 5000 }
  }

  geo_block_countries = ["CN", "RU"]

  providers = {
    aws = aws.use1
  }
}

# La asociación a CloudFront NO se hace con web_acl_association,
# sino con web_acl_id en la propia distribución del cliente:
#
# resource "aws_cloudfront_distribution" "this" {
#   # ...
#   web_acl_id = module.waf.web_acl_arn
# }
