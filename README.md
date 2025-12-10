# Scalable & Secure E-Commerce Platform on AWS ☁️🛒

![AWS](https://img.shields.io/badge/AWS-FF9900?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-005C84?style=for-the-badge&logo=mysql&logoColor=white)

> **ENPM818N - Cloud Computing (Fall 2025)** > **Infrastructure Group Project 6**

## 📖 Project Overview

This project demonstrates the design and deployment of a highly available, secure, and scalable e-commerce infrastructure on AWS using **Terraform**. The platform is designed to handle fluctuating traffic loads while ensuring data security at rest and in transit. It features a 3-tier architecture (Web, App, Data) within a custom VPC, protected by AWS WAF and accelerated by CloudFront.

### 🚀 Key Features

- **Infrastructure as Code:** 100% provisioned via Terraform.
- **High Availability:** Multi-AZ deployment for EC2 and RDS.
- **Auto Scaling:** Dynamic scaling based on CPU (>70%) and Memory metrics.
- **Security First:**
  - AWS WAF protection (SQLi, XSS, Custom Rules).
  - KMS Encryption for RDS and EBS volumes.
  - SSL/TLS encryption in transit.
- **Global Delivery:** CloudFront CDN with S3 Origin Access Control (OAC).
- **Observability:** Comprehensive CloudWatch Dashboards and Alarms.

---

## 🏗️ Architecture

![Architecture Diagram](./architecture_diagram.png)

### Technology Stack

- **Compute:** EC2 (Ubuntu 24.04), Auto Scaling Groups
- **Networking:** VPC, Public/Private Subnets, ALB, NAT Gateway
- **Database:** RDS MySQL (Multi-AZ)
- **Security:** AWS WAF, KMS, Secrets Manager, ACM, Security Groups
- **Storage/CDN:** S3, CloudFront
- **Monitoring:** CloudWatch, SNS, CloudTrail

---

## 🛠️ Deployment Instructions

### Prerequisites

- [Terraform](https://www.terraform.io/) installed (v1.0+)
- AWS CLI configured with appropriate credentials
- An SSH Key Pair created in your AWS region

### Steps

1. **Clone the Repository**

   ```
   git clone https://github.com/sumi0309/enpm818n-fall2025-infrastructure-group-project-6.git
   cd enpm818n-fall2025-infrastructure-group-project-6
   ```

2. **Initialize Terraform**

   ```
   terraform init
   ```

3. **Plan the Infrastructure**
   Review the resources to be created.

   ```
   terraform plan
   ```

4. **Apply Configuration**
   Provision the infrastructure (approx. 10-15 mins).

   ```
   terraform apply --auto-approve
   ```

5. **Access the Application**

   - Once deployed, Terraform will output the **ALB DNS Name**.
   - Open your browser and navigate to: `http://<ALB_DNS_NAME>`
   - (HTTP requests will be automatically redirected to HTTPS if configured).

6. **Cleanup**
   To destroy all resources and avoid costs:

   ```
   terraform destroy --auto-approve
   ```

---

## 🧪 Testing & Validation

- **Stress Testing:** We validated auto-scaling by injecting CPU load using `stress-ng`.
  - _Result:_ ASG successfully scaled out from 1 to 2 instances when CPU > 70%.
- **Security Tests:**
  - **SQL Injection:** Blocked by WAF (`403 Forbidden`).
  - **XSS:** Blocked by WAF (`403 Forbidden`).
  - **Custom Header:** Requests with `x-custom-header: blockme` are blocked.

---

## 👥 Team Members & Contributions

| Member                | Role & Contributions                                                                                                                                             |
| :-------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Sumiran Jaiswal**   | **Database & Security Lead**`<br>`• RDS Multi-AZ & KMS Encryption`<br>`• WAF Implementation (SQLi, XSS Rules)`<br>`• Integration Testing & Final Docs            |
| **Colin Bowes**       | **Networking & Compute Lead**`<br>`• Custom VPC Design (Subnets, Route Tables)`<br>`• ALB & Auto Scaling Group Setup`<br>`• Launch Templates & AMI Configuration |
| **Purav Singla**      | **Security Specialist**`<br>`• SSL/TLS Configuration for Database`<br>`• ACM Certificate Management`<br>`• CloudWatch Scaling Alarms Setup                       |
| **Husain Challawala** | **Observability & Resiliency Lead**`<br>`• CloudWatch Dashboards & SNS Alerts`<br>`• CloudTrail Auditing Setup`<br>`• CPU Stress Testing & Validation            |
| **Anesu Kachambwa**   | **Content Delivery Lead**`<br>`• S3 Static Asset Storage`<br>`• CloudFront CDN with OAC`<br>`• Performance Tuning (GZIP)                                         |

---
