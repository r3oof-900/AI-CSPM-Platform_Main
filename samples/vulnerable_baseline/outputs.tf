output "kms_key_arn" {
  description = "ARN of the protected KMS Customer Managed Key"
  value       = aws_kms_key.payment_key.arn
}

output "iam_role_arn" {
  description = "ARN of the IRSA IAM Role"
  value       = aws_iam_role.eks_payment_kms_role.arn
}

output "iam_policy_arn" {
  description = "ARN of the overprivileged IAM Policy"
  value       = aws_iam_policy.overprivileged_kms_policy.arn
}

output "s3_bucket_arn" {
  description = "ARN of the payment vault S3 bucket"
  value       = aws_s3_bucket.payment_vault.arn
}
