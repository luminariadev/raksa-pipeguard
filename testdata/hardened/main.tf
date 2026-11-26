resource "aws_security_group" "internal_ssh" {
  name = "internal-bastion"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_s3_bucket" "audit_logs" {
  bucket = "example-audit-logs"
  acl    = "private"
}

resource "aws_ebs_volume" "app_data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}
