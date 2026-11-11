variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "eu-north-1"
}

variable "aws_account_id" {
  description = "AWS Account ID for target deployment"
  type        = string
  default     = "853679583136"
}

variable "cluster_name" {
  description = "Name of the target EKS Cluster"
  type        = string
  default     = "production-payment-eks"
}

variable "eks_oidc_id" {
  description = "OIDC Provider ID for the EKS Cluster (hash string from AWS EKS)"
  type        = string
  default     = "EXAMPLED5E21A123456789012345678"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}
