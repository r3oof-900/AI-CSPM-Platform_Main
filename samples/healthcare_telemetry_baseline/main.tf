terraform {
  required_version = ">= 1.5.0"
}

variable "aws_account_id" {
  default = "999888777666"
}

variable "aws_region" {
  default = "eu-central-1"
}

resource "aws_kms_key" "telemetry_cmk_key" {
  description         = "KMS CMK for patient telemetry data"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "patient_records_vault" {
  bucket = "patient-records-vault-999888777666"
}

resource "aws_iam_role" "healthcare_telemetry_iam_role" {
  name = "healthcare_telemetry_iam_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::999888777666:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE:sub" = "system:serviceaccount:telemetry:telemetry-sa"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "overprivileged_telemetry_policy" {
  name = "OverprivilegedTelemetryPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
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

resource "aws_iam_role_policy_attachment" "attach_telemetry" {
  role       = aws_iam_role.healthcare_telemetry_iam_role.name
  policy_arn = aws_iam_policy.overprivileged_telemetry_policy.arn
}
