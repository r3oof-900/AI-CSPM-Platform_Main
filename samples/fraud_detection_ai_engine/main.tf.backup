terraform {
  required_version = ">= 1.5.0"
}

variable "aws_account_id" {
  type    = string
  default = "444555666777"
}

variable "aws_region" {
  type    = string
  default = "me-central-1"
}

provider "aws" {
  region = var.aws_region
}

# ==============================================================================
# 1. AWS KMS Customer Managed Key (CMK) for Bank Fraud Models
# ==============================================================================
resource "aws_kms_key" "fraud_models_cmk" {
  description             = "CMK used to encrypt proprietary bank fraud inference models and customer financial embeddings"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAdminPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.aws_account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "fraud-models-cmk"
    Environment = "production-ai"
    DataClass   = "confidential-banking"
  }
}

# ==============================================================================
# 2. S3 Feature Store Lake (Missing Public Access Block, Logging & Lifecycle)
# ==============================================================================
resource "aws_s3_bucket" "fraud_feature_store_lake" {
  bucket        = "fraud-feature-store-${var.aws_account_id}"
  force_destroy = false

  tags = {
    Name        = "fraud-feature-store-lake"
    Environment = "production-ai"
    EncryptedBy = "fraud-models-cmk"
  }
}

# ==============================================================================
# 3. AWS IAM Role with Overbroad Wildcard OIDC IRSA Trust Policy
# ==============================================================================
resource "aws_iam_role" "fraud_detection_ai_role" {
  name        = "fraud_detection_ai_role"
  description = "Assumed by fraud analytics container workloads via EKS OIDC"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OverbroadEksOidcTrust"
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${var.aws_account_id}:oidc-provider/oidc.eks.${var.aws_region}.amazonaws.com/id/FRAUD_EKS_OIDC"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringLike = {
            "oidc.eks.${var.aws_region}.amazonaws.com/id/FRAUD_EKS_OIDC:sub" = "system:serviceaccount:fraud-analytics:*"
          }
        }
      }
    ]
  })

  tags = {
    Environment = "production-ai"
    Namespace   = "fraud-analytics"
  }
}

# ==============================================================================
# 4. Overprivileged IAM Policy (Lethal Wildcard Decrypt Flaw)
# ==============================================================================
resource "aws_iam_policy" "overprivileged_fraud_kms_policy" {
  name        = "OverprivilegedFraudKmsPolicy"
  description = "Flawed policy granting unconstrained kms:Decrypt and GenerateDataKey on wildcard '*' instead of scoped target CMK"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OverprivilegedWildcardKeyAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ]
        # LETHAL FLAW: Wildcard allows container to decrypt ALL tenant keys across the account
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_fraud_kms" {
  role       = aws_iam_role.fraud_detection_ai_role.name
  policy_arn = aws_iam_policy.overprivileged_fraud_kms_policy.arn
}
