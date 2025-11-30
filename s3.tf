############################################
# S3 BUCKET FOR STATIC CDN ASSETS
############################################

resource "random_id" "cdn_rand" {
  byte_length = 4
}

resource "aws_s3_bucket" "cdn_bucket" {
  bucket = "enpm818n-cdn-bucket-${random_id.cdn_rand.hex}"
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
