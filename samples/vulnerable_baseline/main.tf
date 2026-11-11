terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ==============================================================================
# 1. AWS KMS Customer Managed Key (CMK) - Target Crown Jewel
# ==============================================================================
resource "aws_kms_key" "payment_key" {
  description             = "CMK used to encrypt payment cards, billing data, and customer transactions"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "payment-kms-key-policy"
    Statement = [
      {
        Sid    = "EnableRootAdminPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.aws_account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowPaymentRoleDecryption"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.aws_account_id}:role/eks-payment-kms-role"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "payment-vault-cmk"
    Environment = var.environment
    Compliance  = "pci-dss"
    DataClass   = "restricted-financial"
  }
}

resource "aws_kms_alias" "payment_key_alias" {
  name          = "alias/payment-vault-cmk"
  target_key_id = aws_kms_key.payment_key.key_id
}

# ==============================================================================
# 2. Encrypted Target Storage (S3 Financial Vault)
# ==============================================================================
resource "aws_s3_bucket" "payment_vault" {
  bucket        = "payment-vault-${var.aws_account_id}-${var.environment}"
  force_destroy = false

  tags = {
    Name        = "payment-financial-vault"
    Environment = var.environment
    ProtectedBy = "payment-vault-cmk"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "payment_vault_encryption" {
  bucket = aws_s3_bucket.payment_vault.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.payment_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# ==============================================================================
# 3. AWS IAM Role with Genuine EKS IRSA Trust Policy
# ==============================================================================
resource "aws_iam_role" "eks_payment_kms_role" {
  name        = "eks-payment-kms-role"
  description = "IRSA execution role assumed by production Kubernetes payment-service-sa via OIDC"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EksIrsaWebIdentityFederation"
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${var.aws_account_id}:oidc-provider/oidc.eks.${var.aws_region}.amazonaws.com/id/${var.eks_oidc_id}"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "oidc.eks.${var.aws_region}.amazonaws.com/id/${var.eks_oidc_id}:sub" : "system:serviceaccount:production:payment-service-sa",
            "oidc.eks.${var.aws_region}.amazonaws.com/id/${var.eks_oidc_id}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Environment        = var.environment
    KubernetesNamespace = "production"
    KubernetesServiceAccount = "payment-service-sa"
    SecurityVulnerability = "OverprivilegedKmsWildcardAccess"
  }
}

# ==============================================================================
# 4. Overprivileged IAM Policy (The Research Gap Flaw: Resource = "*")
# ==============================================================================
resource "aws_iam_policy" "overprivileged_kms_policy" {
  name        = "OverprivilegedPaymentKmsPolicy"
  description = "Flawed policy granting wildcard KMS Decrypt across all keys instead of least-privilege target key"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OverprivilegedWildcardKmsDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_overprivileged_kms" {
  role       = aws_iam_role.eks_payment_kms_role.name
  policy_arn = aws_iam_policy.overprivileged_kms_policy.arn
}
