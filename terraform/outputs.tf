# outputs.tf
output "apigw_endpoint_url" {
  value       = "${aws_api_gateway_stage.prod.invoke_url}/intake"
  description = "POST /intake endpoint."
}
output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket_arn" {
  value = aws_s3_bucket.uploads.arn
  description = "S3 bucket ARN where intake attachments land."
  }
    
output "uploads_bucket_name" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket name where intake attachments land."
}

output "uploads_log_bucket_arn" {
  value       = aws_s3_bucket.log.arn
  description = "S3 access log bucket ARN."
}

output "vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "S3 bucket name of the evidence vault. Feed this to capture-evidence.sh --vault."
}


output "encryption_algorithm" {
  description = "Server-side encryption algorithm in effect (SC-28 attestation)."
  value = one([
    for rule in aws_s3_bucket_server_side_encryption_configuration.uploads.rule :
    rule.apply_server_side_encryption_by_default[0].sse_algorithm
  ])
}

output "cmek_main_key_arn" {
  value = aws_kms_key.acme_key.arn
  description = "Customer-managed KMS key ARN for most encryption operations."
}

output "cmek_cloudwatch_log_key_arn" {
  value = aws_kms_key.cloudwatchlog_key.arn
  description = "Customer-managed KMS key ARN for CloudWatch log encryption."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "lambda_dlq_url" {
  value       = aws_sqs_queue.lambda_dlq.url
  description = "URL of the SQS Dead Letter Queue for the intake Lambda."
}

output "api_waf_arn" {
  value       = aws_wafv2_web_acl.api_waf.arn
  description = "ARN of the WAF attached to the API Gateway."
}
output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}
