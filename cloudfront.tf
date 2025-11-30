############################################
# ORIGIN ACCESS CONTROL (OAC)
############################################

resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "enpm818n-oac"
  description                       = "OAC for S3 CDN bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

############################################
# CLOUD FRONT DISTRIBUTION (S3 ORIGIN)
############################################

resource "aws_cloudfront_distribution" "cdn" {
  enabled             = true
  comment             = "enpm818n-cloudfront"
  default_root_object = "index.html"

  # ORIGIN → S3 BUCKET
  origin {
    domain_name = aws_s3_bucket.cdn_bucket.bucket_regional_domain_name
    origin_id   = "enpm818n-s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  # DEFAULT behavior: GET/HEAD + compression
  default_cache_behavior {
    target_origin_id       = "enpm818n-s3-origin"
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

############################################
# BUCKET POLICY → ALLOW CLOUDFRONT ACCESS
############################################

resource "aws_s3_bucket_policy" "cdn_bucket_policy" {
  bucket = aws_s3_bucket.cdn_bucket.id
  policy = data.aws_iam_policy_document.cdn_bucket.json
}

data "aws_iam_policy_document" "cdn_bucket" {
  statement {
    sid    = "AllowCloudFrontAccess"
    effect = "Allow"
    actions = ["s3:GetObject"]
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
