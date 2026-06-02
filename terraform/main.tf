#main.tf
######################################################################
# Acme Health — Patient Intake API (CGE-P Capstone Starter)
#
# This is the workload your capstone repo wraps with GRC controls.
# It is INTENTIONALLY non-compliant. See GAPS.md for the named flaws
# your Rego policies + Terraform overrides are expected to remediate.
######################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = var.environment
      ManagedBy       = "terraform"
      ComplianceScope = "HIPAASecurityRule"
      Workload        = "patient-intake-api"
      DataClass       = "1f0809"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix          = var.suffix != "" ? var.suffix : random_id.suffix.hex
  name_prefix     = "${var.project_name}-${var.environment}"
  table_name      = "${local.name_prefix}-submissions-${local.suffix}"
  uploads_bucket  = "${local.name_prefix}-uploads-${local.suffix}"
  log_name        = "${local.name_prefix}-logs-${local.suffix}"
  key_id          = "${local.name_prefix}-key-${local.suffix}"
  vault_name      = "${local.name_prefix}-grc-evidence-vault-${local.suffix}"
}

######################################################################
# Networking — VPC the learner is expected to put the Lambda inside.
# Two public + two private subnets across two AZs.
######################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${local.name_prefix}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.42.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${local.name_prefix}-private-${count.index}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}
# HIPAA 164.312(a)(2)(iv) / SC-12 / SC-13 / SC-28: Cryptographic key establishment 
# and protection at rest. Customed-owned keys, not AWS-managed keys. 
# 90-day key rotation enabled.
resource "aws_kms_key" "key" {
  description             = "KMS key for acme-health resource encryption"
  enable_key_rotation     = true
  rotation_period_in_days = 90 # Equivalent to 7776000s

  lifecycle {
    prevent_destroy = true # set to "true" for use in production
  }
}
# AWS "Aliases" allows for custom naming conventions
resource "aws_kms_alias" "key" {
  name      = "alias/${local.key_id}"
  target_key_id = aws_kms_key.key.key_id
}

######################################################################
# DynamoDB — submissions table.
# GAP-02: encryption uses AWS-owned default, not a CMK you control.
######################################################################

resource "aws_dynamodb_table" "intake" {
  name         = local.table_name.id
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }
  # HIPAA 164.312(a)(2)(iv): (Addressing GAP-02) server_side_encryption block is added, 
  # defaulting to customer-owned key.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.key.arn
  }

}

######################################################################
# S3 — uploads bucket.
# GAP-01: relies on AWS-managed SSE-S3 (default since 2023) instead of
#         SSE-KMS with a customer CMK. PHI keys are not under customer
#         custody. (Addressed on Lns 107-110, 198-199)
# GAP-03: no bucket policy denying non-TLS requests
#         (aws:SecureTransport). (Addressed on Ln 198-199)
# GAP-04: no versioning. PHI overwrites are unrecoverable.
#
# Note: AWS now defaults new buckets to SSE-S3 + full public access block.
# The "gaps" here are real residual gaps once those defaults are in place.
######################################################################

resource "aws_s3_bucket" "uploads" {
  bucket = aws_s3_bucket.uploads.id
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnforceSecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [ 
        aws_s3_bucket.uploads.arn, 
        "${aws_s3_bucket.uploads.arn}/*"
      ]
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    }]
  })
}

# HIPAA 164.312(a)(2)(iv): (Addressing GAP-01) KMS keys are under customer custody 
# and no longer defaults to AWS-managed keys. 
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.key.arn
    }
    bucket_key_enabled = true
  }
}
# CM-6: Versioning preserves prior object states for recovery and audit.
#HIPAA 164.312(e)(1): (Addressing GAP-04) Versioning enabled. PHI overwrites recoverable.
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}


# AC-3: Access control, explicit deny on every public access vector.
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AU-3 / AU-6: Content of audit records + audit review. Adding and configuring a
# log bucket.
resource "aws_s3_bucket" "log" {
  bucket = aws_s3_bucket.log.id
}

resource "aws_s3_bucket_policy" "log" {
  bucket = aws_s3_bucket.log.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnforceSecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [ 
        aws_s3_bucket.log.arn,
        "${aws_s3_bucket.log.arn}/*"
      ]
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    }]
  })
}

resource "aws_s3_bucket_ownership_controls" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
resource "aws_s3_bucket_acl" "log" {
  depends_on = [aws_s3_bucket_ownership_controls.log]
  bucket     = aws_s3_bucket.log.id
  acl        = "log-delivery-write"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "log" {
  bucket                  = aws_s3_bucket.log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "uploads" {
  bucket        = aws_s3_bucket.uploads.id
  target_bucket = aws_s3_bucket.log.id
  target_prefix = "access-logs/"
}


resource "aws_s3_bucket" "vault" {
  bucket              = "${local.vault_name}"
  object_lock_enabled = true        # MUST be set at bucket creation
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" }   # Object Lock requires versioning
}

resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    default_retention {
      mode = var.lock_mode           # GOVERNANCE for labs, COMPLIANCE for production
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.vault]
}
resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}
resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Refuse bucket deletion from anyone except the account root.
data "aws_caller_identity" "current" {}
resource "aws_s3_bucket_policy" "vault" {
  bucket = aws_s3_bucket.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyBucketDeletion"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:DeleteBucket"
      Resource  = [ 
        aws_s3_bucket.vault.arn,
        "${aws_s3_bucket.vault.arn}/*"
      ]
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    },
    { 
    Statement = [{
        Sid       = "EnforceSecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.vault.arn,
          "${aws_s3_bucket.vault.arn}/*"
        ]
        Condition = {
          Bool    = {
            "aws:SecureTransport" = "false"
          }
        }
      }]
    }]
  })
}
resource "aws_s3_bucket_policy" "vault" {
  bucket = aws_s3_bucket.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
        Sid       = "EnforceSecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.vault.arn,
          "${aws_s3_bucket.vault.arn}/*"
        ]
        Condition = {
          Bool    = {
            "aws:SecureTransport" = "false"
          }
        }
      }]
    })
  }

# (Intentionally omitted: SSE-KMS encryption with a customer CMK,
#  bucket policy enforcing aws:SecureTransport, lifecycle.
#  These are the gaps the learner closes.)

######################################################################
# Lambda — the intake handler.
# GAP-05: not deployed inside the VPC.
# GAP-06: no reserved concurrency, no DLQ, no X-Ray.
# GAP-07: IAM role has dynamodb:* and s3:* on the resources (over-broad).
######################################################################

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${local.name_prefix}-lambda-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# GAP-07: deliberately broad permissions on the workload data stores. HIPAA 164.312(a)(1)
# (Addressing GAP-07 by adding specific read/write permissions [instead of '*'], 
# and creating a Rego policy that blocks admin actions [like deleting tables or 
# changing bucket policies](***consulting AI model Gemini Pro 3.1***))

resource "aws_iam_role_policy" "lambda_intake" {  # Changed "lambda_inline" to "lambda_intake" 
#assuming it was a typo and to preserve naming conventions
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

# HIPAA 164.312(e)(1)GAP-06: No reserved concurrency, no DLQ, no X-Ray. (Addressing GAP-06 by adding a 
# set number of reserved_concurrent_executions '(5)', X-ray Tracing, and DLQ Permissions below. Also adding an SQS queue
# to enable the Dead Letter Queue (DLQ). resources researched added with the help of AI system: "Gemini Pro 3.1")
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { # 1. DynamoDB Read/Write Permissions
        
        Effect   = "Allow"
        Action   = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem",
          "dynamodb:Scan",
          "dynamodb:Query",
          "dynamodb:DescribeTable"
        ]
        Resource = aws_dynamodb_table.intake.arn
      },
      
      # 2. S3 Read/Write Permissions
      {
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = ["${aws_s3_bucket.uploads.arn}", "${aws_s3_bucket.uploads.arn}/*"]
      },
      
      # 3. X-Ray Tracing Permissions
      {
        Effect   = "Allow"
        Action   = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*" 
      },
            # 4. SQS DLQ Permissions
      {
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.lambda_dlq.arn
      },
      # KMS permissions for encrypting DLQ messages
      {
        Effect   = "Allow"
        Action   = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.key.arn
      }
    ]
  })
}
# (resource added with the help of AI system: "Gemini Pro 3.1")
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "intake-handler-dlq"
  # Retain failed messages for 14 days (the maximum)
  message_retention_seconds = 1209600
  # Use Customer-Managed Key (CMK) via the alias
  kms_master_key_id         = aws_kms_alias.key.name
  
  # Best practice: caches the KMS key for 5 minutes to reduce KMS API calls and costs 
  kms_data_key_reuse_period_seconds = 300 
}
resource "aws_lambda_function" "intake" {
  function_name    = "${local.name_prefix}-handler-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 10
  reserved_concurrent_executions = 5
  environment {
    variables = {
      INTAKE_TABLE  = aws_dynamodb_table.intake.name
      UPLOAD_BUCKET = aws_s3_bucket.uploads.id
    }
  }
  tracing_config {
    mode = "Active"
  }

  dead_letter_config {target_arn = aws_sqs_queue.lambda_dlq.arn}


  # HIPAA 164.312(e)(1)GAP-05: no vpc_config block. 
  #Learner expected to add one referencing (Addressing GAP-05 by adding both a 
  # vpc_config block and security group. Also added a resource block to enable 
  # the API to function in the private subnet of the VPC.  )
  
  vpc_config {
    # Using the Private Subnet for Lambda 
    # (resource added with the help of AI system: "Gemini Pro 3.1")
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
}
resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
  
######################################################################
# API Gateway — HTTP API in front of the Lambda.
# GAP-08: 1) no access logging, 2) no throttling, 3) no WAF.
######################################################################
#
# I undersatand that the engineers have created a HTTP API, and 
# I am opting to switch to a REST API# as AWS HTTP API 
# does not natively support AWF WAF. 
#######################################################################

# 1. Creating a CloudWatch Log Group for API Gateway logs
resource "aws_cloudwatch_log_group" "apigw_logs" {
  name              = "/aws/apigateway/${local.name_prefix}-rest-api-${local.suffix}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.key.arn
}
# Switching to REST API for native WAF support (instead of needing to place the 
# CloudFront distribution in front of the AWS HTTP API)
resource "aws_api_gateway_rest_api" "intake" {
  name          = "${local.name_prefix}-rest-api-${local.suffix}"
  description   = "Intake REST API with native WAF integration"
}

resource "aws_api_gateway_resource" "intake" {
  rest_api_id = aws_api_gateway_rest_api.intake.id
  parent_id   = aws_api_gateway_rest_api.intake.root_resource_id
  path_part   = "intake"
}

resource "aws_api_gateway_method" "intake_post" {
  rest_api_id   = aws_api_gateway_rest_api.intake.id
  resource_id   = aws_api_gateway_resource.intake.id
  http_method   = "POST"
  authorization = "NONE"
}
resource "aws_api_gateway_integration" "lambda" {
  rest_api_id                 = aws_api_gateway_rest_api.intake.id
  resource_id                 = aws_api_gateway_resource.intake.id
  http_method                 = aws_api_gateway_method.intake_post.http_method
  integration_http_method     = "POST"
  type                        = "AWS_PROXY"
  uri             = aws_lambda_function.intake.invoke_arn
}

# Deployment and Staging
resource "aws_api_gateway_deployment" "intake" {
  rest_api_id = aws_api_gateway_rest_api.intake.id

# Triggers a redeployment when the API configuration changes
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.intake.id,
      aws_api_gateway_method.intake_post.id,
      aws_api_gateway_integration.lambda.id,
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_apigatewayv2_route" "intake" {
  api_id    = aws_apigatewayv2_api.intake.id
  route_key = "POST /intake"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_api_gateway_stage" "prod" {
  deployment_id = aws_api_gateway_deployment.intake.id
  rest_api_id   = aws_api_gateway_rest_api.intake.id
  stage_name    = "prod"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      sourceIp       = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      responseLength = "$context.responseLength"
    })
  }
}

# 2. Method Settings (Throttling enabled here)
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.intake.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled        = true
    data_trace_enabled     = true
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }
}

# 3. Native Regional WAF and Association
resource "aws_wafv2_web_acl" "api_waf" {
  name        = "${local.name_prefix}-rest-waf-${local.suffix}"
  description = "Native WAF for REST API"
  scope       = "REGIONAL" # Must be REGIONAL for API Gateway

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "rest-waf-metrics"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "api_waf_assoc" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.api_waf.arn
}

# Lambda Permission (Updated for REST API)
resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.intake.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.intake.execution_arn}/*/*"
}

