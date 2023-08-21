terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.13.1"
    }
  }
}

provider "aws" {
   access_key = "XXXXXXXXXXXXX"
   secret_key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
   region = "eu-west-1"
}

data "aws_vpc" "default" {
  default = true
}

resource "aws_vpc" "vpc_test" {
    cidr_block = "10.0.0.0/16"
    enable_dns_support   = true
    enable_dns_hostnames = true
    tags       = {
        Name = "Test VPC"
    }
}

resource "aws_internet_gateway" "internet_gateway" {
    vpc_id = aws_vpc.vpc_test.id
}

resource "aws_subnet" "pub_subnet" {
    vpc_id                  = aws_vpc.vpc_test.id
    cidr_block              = "10.0.0.0/22"
}

resource "aws_route_table" "public" {
    vpc_id = aws_vpc.vpc_test.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.internet_gateway.id
    }
}

resource "aws_route_table_association" "route_table_association" {
    subnet_id      = aws_subnet.pub_subnet.id
    route_table_id = aws_route_table.public.id
}

resource "aws_ecr_repository" "test" {
  name                 = "test"
  image_tag_mutability = "IMMUTABLE"
}

resource "aws_security_group" "db_sg" {
  vpc_id      = aws_vpc.vpc_test.id
  name        = "test-sg"
  description = "Allow all inbound for Postgres"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs_sg" {
    vpc_id      = aws_vpc.vpc_test.id

    ingress {
        from_port       = 22
        to_port         = 22
        protocol        = "tcp"
        cidr_blocks     = ["0.0.0.0/0"]
    }

    ingress {
        from_port       = 443
        to_port         = 443
        protocol        = "tcp"
        cidr_blocks     = ["0.0.0.0/0"]
    }

    egress {
        from_port       = 0
        to_port         = 65535
        protocol        = "tcp"
        cidr_blocks     = ["0.0.0.0/0"]
    }
}

resource "aws_db_instance" "postgres_test" {
  identifier                    = "postgres-test"
  db_name                       = "testdb"
  instance_class                = "db.t3.micro"
  allocated_storage             = 5
  engine                        = "postgres"
  skip_final_snapshot           = true
  publicly_accessible           = true
  vpc_security_group_ids        = [aws_security_group.db_sg.id]
  username                      = "root"
  manage_master_user_password   = true
}

resource "aws_elasticsearch_domain" "es_test" {
  domain_name           = "test-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t2.small.elasticsearch"
  }

  ebs_options {
      ebs_enabled = true
      volume_size = 10
  }
}

# Creating the AWS Elasticsearch domain policy

resource "aws_elasticsearch_domain_policy" "main" {
  domain_name = aws_elasticsearch_domain.es_test.domain_name
  access_policies = <<POLICIES
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "es:*",
            "Principal": "*",
            "Effect": "Allow",
            "Condition": {
                "IpAddress": {"aws:SourceIp": "127.0.0.1/32"}
            },
            "Resource": "${aws_elasticsearch_domain.es_test.arn}/*"
        }
    ]
}
POLICIES
}

resource "aws_elasticache_cluster" "redis_test" {
  cluster_id           = "redis-test"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis3.2"
  engine_version       = "3.2.10"
  port                 = 6379
}

resource "aws_s3_bucket" "bucket_test" {
  bucket = "my-tf-test-bucket-fr"
}

data "aws_iam_policy_document" "ecs_agent" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "asg_cloudwatch_logs_policy" {
  name = "ASGCloudWatchLogsPolicy"

  # Define the policy document allowing CloudWatch Logs permissions
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ],
        Effect = "Allow",
        Resource = "*",
      },
      {
        Action =[
          "sts:AssumeRole"
        ],
        Effect = "Allow",
        Resource = "*"
      }
    ],
  })
}

resource "aws_iam_role" "ecs_agent" {
  name               = "ecs-agent"
  assume_role_policy = data.aws_iam_policy_document.ecs_agent.json
}


resource "aws_iam_role_policy_attachment" "ecs_agent" {
  role       =  aws_iam_role.ecs_agent.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "ecs_agent" {
  name = "ecs-agent"
  role = aws_iam_role.ecs_agent.name
}

resource "aws_launch_configuration" "ecs_launch_config" {
    image_id             = "ami-094d4d00fd7462815"
    iam_instance_profile = aws_iam_instance_profile.ecs_agent.name
    security_groups      = [aws_security_group.ecs_sg.id]
    user_data = <<-EOF
      #!/bin/bash
      yum install -y awslogs
      systemctl start awslogsd
      systemctl enable awslogsd
    EOF
    instance_type        = "t2.micro"
}

resource "aws_autoscaling_group" "failure_analysis_ecs_asg" {
    name                      = "asg"
    vpc_zone_identifier       = [aws_subnet.pub_subnet.id]
    launch_configuration      = aws_launch_configuration.ecs_launch_config.name

    desired_capacity          = 2
    min_size                  = 1
    max_size                  = 10
    health_check_grace_period = 300
    health_check_type         = "EC2"
}

resource "aws_ecs_cluster" "ecs_cluster_test" {
    name  = "test-cluster"
}

resource "aws_ecs_task_definition" "task_definition" {
  family                = "worker"
  container_definitions = <<EOF
  [
    {
      "name": "test-app",
      "image": "572631958906.dkr.ecr.eu-west-1.amazonaws.com/test:latest",
      "memory": 512,
      "cpu": 2,
      "portMappings": [
        {
          "containerPort": 3000,
          "hostPort": 3000
        }
      ],
      "environment": [
        {
          "name": "REDIS_URL",
          "value": "redis-test.kdsmf6.0001.euw1.cache.amazonaws.com"
        },
        {
          "name": "ELASTICACHE_URL",
          "value": "https://search-test-domain-gubjecuqhnxhdxtw5za7laisqq.eu-west-1.es.amazonaws.com"
        },
        {
          "name": "BUCKET_NAME",
          "value": "my-tf-test-bucket-fr"
        },
        {
          "name": "AWS_REGION",
          "value": "eu-west-1"
        },
        {
          "name": "DB_URL",
          "value": "testdb.gubjecuqhnxhdxtw5za7laisqq.eu-west-1.rds.amazonaws.com"
        },
        {
          "name": "AWS_SECRET_KEY",
          "value": "xxxxxxxx"
        },
        {
          "name": "AWS_ACCESS_KEY",
          "value": "xxxxxxxx"
        }
      ]
    }
  ]
  EOF
}

resource "aws_lb" "test_alb" {
  name               = "my-alb-test"
  internal           = false
  load_balancer_type = "application"
  subnets            = aws_subnet.pub_subnet[*].id
  enable_deletion_protection = false
}

resource "aws_lb_listener" "my_alb_listener" {
  load_balancer_arn = aws_lb.my_alb.arn
  port              = 443  # SSL port
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"

  certificate_arn = "your-ssl-certificate-arn"
}


resource "aws_ecs_service" "worker" {
  name            = "worker"
  cluster         = aws_ecs_cluster.ecs_cluster_test.id
  task_definition = aws_ecs_task_definition.task_definition.arn
  desired_count   = 2
}


resource "aws_iam_role" "s3_access_role" {
  name = "s3_access_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "s3_access_policy" {
  name        = "s3_access_policy"
  description = "Policy for S3 read and write access"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ],
        Effect   = "Allow",
        Resource = [
          "arn:aws:s3:::my-tf-test-bucket-fr/*",
          "arn:aws:s3:::my-tf-test-bucket-fr"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "s3_access_attachment" {
  policy_arn = aws_iam_policy.s3_access_policy.arn
  role       = aws_iam_role.s3_access_role.name
}

resource "aws_cloudwatch_log_group" "asg_logs" {
  name              = "/aws/autoscaling/my-asg-logs"
  retention_in_days = 15
}

resource "aws_cloudwatch_log_group" "alb_logs" {
  name              = "/aws/loadbalancer/my-alb-logs"
  retention_in_days = 15
}

