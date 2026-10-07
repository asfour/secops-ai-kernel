terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "secops_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "secops-isolated-vpc-network"
  }
}

resource "aws_subnet" "secops_private_subnet" {
  vpc_id            = aws_vpc.secops_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name = "secops-hypervisor-core-subnet"
  }
}

resource "aws_instance" "secops_metal_node" {
  ami           = "ami-053b0d53c279acc90" # Clean Ubuntu Server 24.04 LTS Reference
  instance_type = "m6i.metal"             # Bare-metal instance supporting native nested virtualization

  subnet_id = aws_subnet.secops_private_subnet.id

  user_data = <<-EOF
              #!/usr/bin/env bash
              set -euo pipefail
              apt-get update -y
              apt-get install -y git build-essential devscripts libbpf-dev
              
              # Enable nested virtualization runtime permissions
              modprobe kvm_intel
              chmod a+rw /dev/kvm
              EOF

  tags = {
    Name = "secops-kernel-baremetal-host"
  }
}
