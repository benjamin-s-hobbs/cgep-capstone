# variables.tf
variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Short project identifier. Becomes part of bucket names and the Project tag."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name must be 3-21 lowercase alphanumerics or hyphens, starting with a letter."
  }
}
variable "environment" {
  type        = string
  description = "Deployment environment. Drives the Environment tag and downstream policy decisions."
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}
variable "suffix" {
  type        = string
  description = "Optional suffix to force a specific resource name. Defaults to a random_id."
  default     = ""
}

variable "lock_mode" {
  type        = string
  description = "GOVERNANCE for lab work; COMPLIANCE for real evidence."
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "retention_days" {
  type        = number
  description = "Default retention applied to every uploaded object."
  default     = 1
}