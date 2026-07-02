output "cspm_scanner_username" {
  description = "IAM username for the CSPM scanner"
  value       = aws_iam_user.cspm_scanner.name
}

output "cspm_scanner_access_key_id" {
  description = "Access key ID for the CSPM scanner user"
  value       = aws_iam_access_key.cspm_scanner_key.id
}

output "cspm_scanner_secret_access_key" {
  description = "Secret access key for the CSPM scanner user"
  value       = aws_iam_access_key.cspm_scanner_key.secret
  sensitive   = true
}
