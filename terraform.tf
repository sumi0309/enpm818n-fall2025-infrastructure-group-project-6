terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.21.0"
    }
  }
  required_version = ">= 1.14.0"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.5.1"
}

module "s3-bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "5.8.2"
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "10.2.0"
}

module "ec2-instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "6.1.4"
}

module "security-group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.3.1"
}

module "kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "4.1.1"
}

module "autoscaling" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "9.0.2"
  name    = "app-autoscale-group"
}

module "cloudwatch" {
  source  = "terraform-aws-modules/cloudwatch/aws"
  version = "5.7.2"
}

module "rds" {
  source     = "terraform-aws-modules/rds/aws"
  version    = "6.13.1"
  identifier = "app-rds-instance"
}