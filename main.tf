terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.21.0"
    }
    # Added TLS provider for SSL/ACM 
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.14.0"
}

provider "aws" {
  region                   = "us-east-1"
  shared_config_files      = ["$HOME/.aws/config"]
  shared_credentials_files = ["$HOME/.aws/credentials"]
  profile                  = "PowerUserAccess-408876511723"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "enpm818n-vpc"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "enpm818n-public-subnet-${count.index}"
  }
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Name = "enpm818n-private-subnet-${count.index}"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "enpm818n-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "enpm818n-public-rt" }
}

resource "aws_route_table_association" "public_assoc" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  count                     = 3
  domain                    = "vpc"
  associate_with_private_ip = "10.0.${count.index + 4}.2"
  depends_on                = [aws_internet_gateway.igw]
  tags = {
    Name = "enpm818n-nat-eip-${count.index}"
  }
}

resource "aws_nat_gateway" "nat" {
  count         = length(var.private_subnet_cidrs)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.private[count.index].id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "enpm818n-nat-gateway-${count.index}"
  }
}

resource "aws_route_table" "private" {
  count  = length(var.private_subnet_cidrs)
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[count.index].id
  }
  tags = { Name = "enpm818n-private-rt-${count.index}" }
}

resource "aws_route_table_association" "private_assoc" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# --- ACM / SSL Setup ---
resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "example" {
  private_key_pem = tls_private_key.example.private_key_pem

  subject {
    common_name  = "example.com"
    organization = "ENPM818N Lab"
  }
  validity_period_hours = 12
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "aws_acm_certificate" "cert" {
  private_key      = tls_private_key.example.private_key_pem
  certificate_body = tls_self_signed_cert.example.cert_pem
  tags = {
    Name = "enpm818n-self-signed-cert"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
  owners = ["099720109477"] # Canonical
}

resource "aws_launch_template" "app_template" {
  name = "enpm818n-app-template"
  image_id               = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  user_data              = base64encode(file("./userdata.sh"))
  vpc_security_group_ids = [aws_security_group.instances.id]
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.instances.id]
  }
  monitoring {
    enabled = true
  }
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 20
      volume_type = "gp3"
      encrypted   = true
    }
  }
}

resource "aws_autoscaling_group" "asg" {
  name = "enpm818n-asg"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 3
  vpc_zone_identifier = aws_subnet.public[*].id
  target_group_arns   = [aws_lb_target_group.alb_tg.arn]

  launch_template {
    id      = aws_launch_template.app_template.id
    version = "$Latest"
  }
}

# --- CHANGED: Explicit Scaling Policies for Alarms ---
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "enpm818n-scale-out"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.asg.name
}

resource "aws_autoscaling_policy" "scale_in" {
  name                   = "enpm818n-scale-in"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.asg.name
}

resource "aws_autoscaling_policy" "memory_policy" {
  name                   = "enpm818n-memory-policy"
  autoscaling_group_name = aws_autoscaling_group.asg.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    customized_metric_specification {
      metric_name = "MemoryUtilization"
      namespace   = "AWS/EC2"
      statistic   = "Average"
    }
    target_value = 70.0
  }
}

resource "aws_lb" "alb" {
  name                       = "enpm818n-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  enable_deletion_protection = false
}

resource "aws_lb_target_group" "alb_tg" {
  name     = "enpm818n-alb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/"
    protocol            = "HTTP"
    interval            = 30
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }
}

# --- CHANGED: Listeners for SSL ---
# Redirect HTTP to HTTPS
resource "aws_lb_listener" "alb_listener_http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# HTTPS Listener
resource "aws_lb_listener" "alb_listener_https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_tg.arn
  }
}
# ----------------------------------

resource "aws_security_group" "alb" {
  name        = "enpm818n-alb-sg"
  description = "Allow inbound HTTP traffic and all outbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # Added HTTPS ingress
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "enpm818n-alb-sg"
  }
}

resource "aws_security_group" "instances" {
  name        = "enpm818n-web-sg"
  description = "Allow HTTP from ALB and all outbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "enpm818n-web-sg"
  }
}

resource "aws_db_subnet_group" "rds" {
  name       = "enpm818n-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id
  tags = {
    Name = "enpm818n-db-subnet-group"
  }
}


data "aws_iam_policy_document" "rds_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "enpm818n-rds-monitoring-role"
  assume_role_policy = data.aws_iam_policy_document.rds_assume_role.json

  tags = {
    Name = "enpm818n-rds-monitoring-role"
  }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_attachment" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "rds" {
  identifier                  = "enpm818n-rds-db"
  allocated_storage           = 20
  max_allocated_storage       = 100 
  storage_type                = "gp2"
  db_name                     = "mydb"
  engine                      = "mysql"
  engine_version              = "8.0.43"
  instance_class              = "db.m5.large"
  username                    = "admin"
  manage_master_user_password = true 
  parameter_group_name        = "default.mysql8.0"
  skip_final_snapshot         = true
  db_subnet_group_name        = aws_db_subnet_group.rds.name
  vpc_security_group_ids      = [aws_security_group.rds.id]
  multi_az                    = true
  storage_encrypted           = true


  performance_insights_enabled          = true
  performance_insights_retention_period = 7 
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn

  deletion_protection = true

  backup_retention_period = 7
  backup_window           = "03:00-06:00"
  maintenance_window      = "Mon:00:00-Mon:03:00"

  tags = {
    Name = "enpm818n-rds-db"
  }
}

resource "aws_security_group" "rds" {
  name        = "enpm818n-db-sg"
  description = "Allow MySQL from app instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "MySQL from app instances"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.instances.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
   tags = {
    Name = "enpm818n-db-sg"
  }
}

resource "aws_wafv2_web_acl" "main" {
  name        = "enpm818n-waf-web-acl"
  description = "WAF Web ACL for ALB"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # WAF Rules for SQLi
  rule {
    name     = "AWS-AWSManagedRulesSQLiRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "enpm818n-waf-sqli"
      sampled_requests_enabled   = true
    }
  }

  # WAF Rules for XSS (Part of Common Rule Set)
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "enpm818n-waf-common"
      sampled_requests_enabled   = true
    }
  }

  # : WAF custom rule
  # This rule blocks requests containing "blockme" in the "x-custom-header" header
  rule {
    name     = "enpm818n-custom-block-rule"
    priority = 30

    action {
      block {}
    }

    statement {
      byte_match_statement {
        search_string = "blockme"
        field_to_match {
          single_header {
            name = "x-custom-header"
          }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
        positional_constraint = "CONTAINS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "enpm818n-waf-custom"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "enpm818n-waf-main"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "enpm818n-waf-web-acl"
  }
}

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}


resource "random_id" "cdn_rand" {
  byte_length = 4
}

resource "aws_s3_bucket" "cdn_bucket" {
  bucket        = "enpm818n-cdn-bucket-${random_id.cdn_rand.hex}"
  force_destroy = true

  tags = {
    Name = "enpm818n-cdn-bucket"
  }
}

# Secure bucket (required to use with CloudFront)
resource "aws_s3_bucket_public_access_block" "cdn_bucket_block" {
  bucket                  = aws_s3_bucket.cdn_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "enpm818n-oac"
  description                       = "OAC for S3 CDN bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}


resource "aws_cloudfront_distribution" "cdn" {
  enabled             = true
  comment             = "enpm818n-cloudfront"
  default_root_object = "index.html"

  # ORIGIN → S3 BUCKET
  origin {
    domain_name              = aws_s3_bucket.cdn_bucket.bucket_regional_domain_name
    origin_id                = "enpm818n-s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  # DEFAULT behavior: GET/HEAD + compression
  default_cache_behavior {
    target_origin_id       = "enpm818n-s3-origin"
    # SSL : Redirect HTTP to HTTPS
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD"]
    cached_methods  = ["GET", "HEAD"]

    # AWS managed CachingOptimized policy → includes GZIP/Brotli
    cache_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "enpm818n-cloudfront"
  }
}


resource "aws_s3_bucket_policy" "cdn_bucket_policy" {
  bucket = aws_s3_bucket.cdn_bucket.id
  policy = data.aws_iam_policy_document.cdn_bucket.json
}

data "aws_iam_policy_document" "cdn_bucket" {
  statement {
    sid    = "AllowCloudFrontAccess"
    effect = "Allow"

    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.cdn_bucket.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.cdn.arn]
    }
  }
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "enpm818n-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric",
        properties = {
          title = "ALB TargetResponseTime (Latency)"
          metrics = [
            [ "AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.alb.arn_suffix ],
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type = "metric",
        properties = {
          title = "ALB 5XX Error Count"
          metrics = [
            [ "AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", aws_lb.alb.arn_suffix ],
          ]
          period = 60
          stat   = "Sum"
        }
      },
      {
        type = "metric",
        properties = {
          title = "ASG CPU Utilization"
          metrics = [
            [ "AWS/EC2", "CPUUtilization", "AutoScalingGroupName", aws_autoscaling_group.asg.name ],
          ]
          period = 60
          stat   = "Average"
        }
      }
    ]
  })
}

resource "aws_sns_topic" "alerts" {
  name = "enpm818n-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = "chalhus@umd.edu"  
}

resource "aws_cloudwatch_metric_alarm" "alb_latency_high" {
  alarm_name          = "enpm818n-alb-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 0.5
  alarm_description   = "ALB latency above 0.5s"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
  }
}

# --- CPU Alarms for ASG Scaling (Alarms trigger scaling) ---
resource "aws_cloudwatch_metric_alarm" "high_cpu_alarm" {
  alarm_name          = "enpm818n-high-cpu-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 70
  alarm_description   = "Scale out if CPU > 70%"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }
  alarm_actions = [aws_autoscaling_policy.scale_out.arn]
}

resource "aws_cloudwatch_metric_alarm" "low_cpu_alarm" {
  alarm_name          = "enpm818n-low-cpu-alarm"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 30
  alarm_description   = "Scale in if CPU < 30%"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }
  alarm_actions = [aws_autoscaling_policy.scale_in.arn]
}
# --------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "alb_5xx_errors" {
  alarm_name          = "enpm818n-alb-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "ALB 5XX errors detected"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
  }
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "enpm818n-cloudtrail-logs-${random_id.cdn_rand.hex}"
  force_destroy = true
}

# --- CloudTrail Bucket Policy (Required for CloudTrail to function) ---
resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}
# -------------------------------------------------------------------------

resource "aws_cloudtrail" "main" {
  name                          = "enpm818n-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_policy]
}