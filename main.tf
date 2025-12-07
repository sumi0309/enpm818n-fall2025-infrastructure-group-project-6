terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.21.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.0.0"
}

provider "aws" {
  region                   = "us-east-1"
  shared_config_files      = ["$HOME/.aws/config"]
  shared_credentials_files = ["$HOME/.aws/credentials"]
  profile                  = "PowerUserAccess-408876511723"
}

# --- VPC & Networking (Naming: enpm818n-*) ---

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

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "enpm818n-public-subnet-${count.index}"
  }
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 4}.0/24"
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
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  count      = 3
  domain     = "vpc"
  depends_on = [aws_internet_gateway.igw]
  tags = {
    Name = "enpm818n-nat-eip-${count.index}"
  }
}

resource "aws_nat_gateway" "nat" {
  count         = 3
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.private[count.index].id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "enpm818n-nat-gateway-${count.index}"
  }
}

resource "aws_route_table" "private" {
  count  = 3
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[count.index].id
  }
  tags = { Name = "enpm818n-private-rt-${count.index}" }
}

resource "aws_route_table_association" "private_assoc" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# --- ACM & SSL (Phase 2: Encrypt Data in Transit) ---

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
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]
}

resource "aws_acm_certificate" "cert" {
  private_key      = tls_private_key.example.private_key_pem
  certificate_body = tls_self_signed_cert.example.cert_pem
  tags = {
    Name = "enpm818n-self-signed-cert"
  }
}

# --- Compute: EC2, Launch Template, ASG (Phase 1) ---

data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
  owners = ["099720109477"]
}

resource "aws_launch_template" "app_template" {
  name          = "enpm818n-app-template"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"

  # Requirement: Install stress-ng and E-commerce platform
  user_data = base64encode(<<-EOF
              #!/bin/bash
              apt-get update -y
              
              # Requirement: Install stress-ng
              apt-get install -y stress-ng
              
              # Install Web Server (Apache/PHP) for E-Commerce
              apt-get install -y apache2 php php-mysql git
              systemctl start apache2
              systemctl enable apache2
              
              # Requirement: Download and deploy E-Commerce Platform
              cd /var/www/html
              rm index.html
              # REPLACE THE LINK BELOW WITH YOUR SPECIFIC REPO URL
              # git clone https://github.com/your-repo/ecommerce-platform.git .
              
              echo "<h1>ENPM818N Project - App Ready</h1>" > index.html
              EOF
  )

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.instances.id]
  }

  monitoring {
    enabled = true
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 20
      volume_type = "gp3"
      encrypted   = true
    }
  }
  tags = { Name = "enpm818n-launch-template" }
}

resource "aws_autoscaling_group" "asg" {
  name                = "enpm818n-asg"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 3
  vpc_zone_identifier = aws_subnet.public[*].id
  target_group_arns   = [aws_lb_target_group.alb_tg.arn]

  launch_template {
    id      = aws_launch_template.app_template.id
    version = "$Latest"
  }

  # Requirement: Resource tags
  tag {
    key                 = "Name"
    value               = "enpm818n-webserver"
    propagate_at_launch = true
  }
}

# --- ASG Scaling Policies (Phase 1) ---

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

# --- Load Balancer (Phase 1) ---

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
    path = "/" # Ensure this path exists in your app
  }
}

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

resource "aws_security_group" "alb" {
  name   = "enpm818n-alb-sg"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
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
  tags = { Name = "enpm818n-alb-sg" }
}

resource "aws_security_group" "instances" {
  name   = "enpm818n-web-sg"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  ingress {
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
  tags = { Name = "enpm818n-web-sg" }
}

# --- RDS (Phase 1) ---

resource "aws_db_subnet_group" "rds" {
  name       = "enpm818n-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id
  tags = { Name = "enpm818n-db-subnet-group" }
}

resource "aws_iam_role" "rds_monitoring" {
  name = "enpm818n-rds-monitoring-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
    }]
  })
  tags = { Name = "enpm818n-rds-monitoring-role" }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_attachment" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "rds" {
  identifier                   = "enpm818n-rds-db"
  allocated_storage            = 20
  max_allocated_storage        = 100
  storage_type                 = "gp2"
  db_name                      = "mydb"
  engine                       = "mysql"
  engine_version               = "8.0.43"
  instance_class               = "db.m5.large"
  username                     = "admin"
  manage_master_user_password  = true
  skip_final_snapshot          = true
  db_subnet_group_name         = aws_db_subnet_group.rds.name
  vpc_security_group_ids       = [aws_security_group.rds.id]
  multi_az                     = true
  storage_encrypted            = true # Uses default KMS
  performance_insights_enabled = true
  monitoring_interval          = 60
  monitoring_role_arn          = aws_iam_role.rds_monitoring.arn
  tags = { Name = "enpm818n-rds-db" }
}

resource "aws_security_group" "rds" {
  name   = "enpm818n-db-sg"
  vpc_id = aws_vpc.main.id
  ingress {
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
  tags = { Name = "enpm818n-db-sg" }
}

# --- WAF (Phase 2) ---

resource "aws_wafv2_web_acl" "main" {
  name        = "enpm818n-waf-web-acl"
  description = "WAF Web ACL for ALB"
  scope       = "REGIONAL"
  default_action {
    allow {}
  }

  # Rule 1: SQL Injection
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

  # Rule 2: XSS
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

  # Rule 3: Custom Rule
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
  tags = { Name = "enpm818n-waf-web-acl" }
}

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# --- CloudFront & S3 (Phase 3) ---

resource "random_id" "cdn_rand" { byte_length = 4 }

resource "aws_s3_bucket" "cdn_bucket" {
  bucket        = "enpm818n-cdn-bucket-${random_id.cdn_rand.hex}"
  force_destroy = true
  tags = { Name = "enpm818n-cdn-bucket" }
}

resource "aws_s3_bucket_public_access_block" "cdn_bucket_block" {
  bucket                  = aws_s3_bucket.cdn_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "enpm818n-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled             = true
  comment             = "enpm818n-cloudfront"
  default_root_object = "index.html"

  origin {
    domain_name              = aws_s3_bucket.cdn_bucket.bucket_regional_domain_name
    origin_id                = "enpm818n-s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  default_cache_behavior {
    target_origin_id       = "enpm818n-s3-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized (GZIP enabled)
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate { cloudfront_default_certificate = true }
  tags = { Name = "enpm818n-cloudfront" }
}

resource "aws_s3_bucket_policy" "cdn_bucket_policy" {
  bucket = aws_s3_bucket.cdn_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "AllowCloudFrontAccess"
      Effect = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action = "s3:GetObject"
      Resource = "${aws_s3_bucket.cdn_bucket.arn}/*"
      Condition = {
        StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.cdn.arn }
      }
    }]
  })
}

# --- Monitoring & Alarms (Phase 3 & 4) ---

resource "aws_sns_topic" "alerts" {
  name = "enpm818n-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = "chalhus@umd.edu"
}

# Requirement: Alarm name prefix enpm818n-cpu
resource "aws_cloudwatch_metric_alarm" "high_cpu_alarm" {
  alarm_name          = "enpm818n-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 70
  alarm_description   = "Scale out if CPU > 70%"
  dimensions = { AutoScalingGroupName = aws_autoscaling_group.asg.name }
  alarm_actions = [aws_autoscaling_policy.scale_out.arn]
}

resource "aws_cloudwatch_metric_alarm" "low_cpu_alarm" {
  alarm_name          = "enpm818n-cpu-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 30
  alarm_description   = "Scale in if CPU < 30%"
  dimensions = { AutoScalingGroupName = aws_autoscaling_group.asg.name }
  alarm_actions = [aws_autoscaling_policy.scale_in.arn]
}

# Requirement: Alarm name prefix enpm818n-custom (Using Memory)
resource "aws_cloudwatch_metric_alarm" "memory_high" {
  alarm_name          = "enpm818n-custom-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "MemoryUtilization" # Requires stress-ng or CloudWatch agent to populate
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Trigger scale out on Memory > 80%"
  dimensions = { AutoScalingGroupName = aws_autoscaling_group.asg.name }
  alarm_actions = [aws_autoscaling_policy.scale_out.arn]
}

# Requirement: Alarm name prefix enpm818n-latency (> 500ms = 0.5s)
resource "aws_cloudwatch_metric_alarm" "alb_latency_high" {
  alarm_name          = "enpm818n-latency-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 0.5
  alarm_description   = "Latency > 500ms"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = { LoadBalancer = aws_lb.alb.arn_suffix }
}

# Requirement: Alarm name prefix enpm818n-errorrates (> 1%)
# Note: This uses Metric Math to calculate percentage (5XX / Requests * 100)
resource "aws_cloudwatch_metric_alarm" "error_rate_high" {
  alarm_name          = "enpm818n-errorrates-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 1 # 1 Percent
  alarm_description   = "5XX Error Rate > 1%"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  metric_query {
    id          = "e1"
    expression  = "(m1 / m2) * 100"
    label       = "Error Rate %"
    return_data = true
  }

  metric_query {
    id = "m1"
    metric {
      metric_name = "HTTPCode_ELB_5XX_Count"
      namespace   = "AWS/ApplicationELB"
      period      = 60
      stat        = "Sum"
      dimensions = { LoadBalancer = aws_lb.alb.arn_suffix }
    }
  }

  metric_query {
    id = "m2"
    metric {
      metric_name = "RequestCount"
      namespace   = "AWS/ApplicationELB"
      period      = 60
      stat        = "Sum"
      dimensions = { LoadBalancer = aws_lb.alb.arn_suffix }
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
          title = "ALB Latency & Errors"
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.alb.arn_suffix],
            [".", "HTTPCode_ELB_5XX_Count", ".", "."]
          ]
          period = 60
          stat   = "Average"
        }
      }
    ]
  })
}

# --- CloudTrail (Phase 4) ---

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "enpm818n-cloudtrail-logs-${random_id.cdn_rand.hex}"
  force_destroy = true
  tags = { Name = "enpm818n-cloudtrail-logs" }
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "enpm818n-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_policy]
  tags = { Name = "enpm818n-cloudtrail" }
}