# Scalable & Secure E-Commerce Platform on AWS ☁🛒

![AWS](https://img.shields.io/badge/AWS-FF9900?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-005C84?style=for-the-badge&logo=mysql&logoColor=white)

> _ENPM818N - Cloud Computing (Fall 2025)_ > _Infrastructure Group Project 6_

## 📖 Project Overview

This project demonstrates the design and deployment of a highly available, secure, and scalable e-commerce infrastructure on AWS using _Terraform_. The platform is designed to handle fluctuating traffic loads while ensuring data security at rest and in transit. It features a 3-tier architecture (Web, App, Data) within a custom VPC, protected by AWS WAF and accelerated by CloudFront.

### 🚀 Key Features

- _Infrastructure as Code:_ 100% provisioned via Terraform.
- _High Availability:_ Multi-AZ deployment for EC2 and RDS.
- _Auto Scaling:_ Dynamic scaling based on CPU (>70%) and Memory metrics.
- _Security First:_
  - AWS WAF protection (SQLi, XSS, Custom Rules).
  - KMS Encryption for RDS and EBS volumes.
  - SSL/TLS encryption in transit.
- _Global Delivery:_ CloudFront CDN with S3 Origin Access Control (OAC).
- _Observability:_ Comprehensive CloudWatch Dashboards and Alarms.

---

## 🏗 Architecture

![Architecture Diagram](./architecture_diagram.png)

### Technology Stack

- _Compute:_ EC2 (Ubuntu 24.04), Auto Scaling Groups
- _Networking:_ VPC, Public/Private Subnets, ALB, NAT Gateway
- _Database:_ RDS MySQL (Multi-AZ)
- _Security:_ AWS WAF, KMS, Secrets Manager, ACM, Security Groups
- _Storage/CDN:_ S3, CloudFront
- _Monitoring:_ CloudWatch, SNS, CloudTrail

---

## 🛠 Deployment Instructions

### Prerequisites

- [Terraform](https://www.terraform.io/) installed (v1.0+)
- AWS CLI configured with appropriate credentials
- An SSH Key Pair created in your AWS region

### Steps

1. _Clone the Repository_

   git clone https://github.com/sumi0309/enpm818n-fall2025-infrastructure-group-project-6.git
   cd enpm818n-fall2025-infrastructure-group-project-6

2. _Initialize Terraform_

   terraform init

3. _Plan the Infrastructure_
   Review the resources to be created.

   terraform plan

4. _Apply Configuration_
   Provision the infrastructure (approx. 10-15 mins).

   terraform apply --auto-approve

5. _Access the Application_

   - Once deployed, Terraform will output the _ALB DNS Name_.
   - Open your browser and navigate to: http://<ALB_DNS_NAME>
   - (HTTP requests will be automatically redirected to HTTPS if configured).

6. _Cleanup_
   To destroy all resources and avoid costs:

   terraform destroy --auto-approve

---

## 🧪 Testing & Validation

- _Stress Testing:_ We validated auto-scaling by injecting CPU load using stress-ng.
  - Result: ASG successfully scaled out from 1 to 2 instances when CPU > 70%.
- _Security Tests:_
  - _SQL Injection:_ Blocked by WAF (403 Forbidden).
  - _XSS:_ Blocked by WAF (403 Forbidden).
  - _Custom Header:_ Requests with x-custom-header: blockme are blocked.

---

## 👥 Team Members & Contributions

| Member              | Role & Contributions                                                                                                                                             |
| :------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| _Sumiran Jaiswal_   | _Database & Security Lead_ `<br>`• RDS Multi-AZ & KMS Encryption `<br>`• WAF Implementation (SQLi, XSS Rules)`<br>`• Integration Testing & Final Docs            |
| _Colin Bowes_       | _Networking & Compute Lead_ `<br>`• Custom VPC Design (Subnets, Route Tables)`<br>`• ALB & Auto Scaling Group Setup `<br>`• Launch Templates & AMI Configuration |
| _Purav Singla_      | _Security Specialist_ `<br>`• SSL/TLS Configuration for Database `<br>`• ACM Certificate Management `<br>`• CloudWatch Scaling Alarms Setup                      |
| _Husain Challawala_ | _Observability & Resiliency Lead_ `<br>`• CloudWatch Dashboards & SNS Alerts `<br>`• CloudTrail Auditing Setup `<br>`• CPU Stress Testing & Validation           |
| _Anesu Kachambwa_   | _Content Delivery Lead_ `<br>`• S3 Static Asset Storage `<br>`• CloudFront CDN with OAC `<br>`• Performance Tuning (GZIP)                                        |

---
