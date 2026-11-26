resource "aws_security_group" "open_admin" {
  name = "open-ssh-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public_artifacts" {
  bucket = "example-public-bucket"
  acl    = "public-read"
}

resource "aws_ebs_volume" "unencrypted_disk" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = false
}
