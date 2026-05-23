AWS Cloud Misconfiguration Scanner
> Python-based security scanner that checks AWS environments for common misconfigurations across IAM, S3, EC2, and CloudTrail. Includes demo mode — no AWS account required to run.
---
What It Does
This tool scans an AWS environment and identifies security misconfigurations that are commonly exploited in real-world breaches. Each finding includes a severity rating and concrete remediation step.
Supports two modes:
Demo mode — runs with realistic sample data, no AWS account needed
Live mode — connects to a real AWS account via boto3 and scans live resources
---
Skills Demonstrated
Area	Detail
Cloud Security	AWS IAM, S3, EC2, CloudTrail security controls
Python	boto3 SDK, CLI tooling, JSON/Markdown report generation
Security Engineering	Misconfiguration detection, severity rating, remediation advice
CIS Benchmarks	Checks aligned to CIS AWS Foundations Benchmark
Threat Awareness	Each check maps to a real-world attack vector
---
Checks Covered
IAM
Check	Severity
Root account MFA enabled	Critical
Console users MFA enabled	Medium
Access key rotation (90 day threshold)	High
Overprivileged IAM policies (AdministratorAccess)	High
S3
Check	Severity
Public bucket access	Critical
Server-side encryption enabled	High
EC2
Check	Severity
SSH (port 22) open to 0.0.0.0/0	Critical
RDP (port 3389) open to 0.0.0.0/0	Critical
EBS volume encryption	Medium
IMDSv2 enforced	Medium
CloudTrail
Check	Severity
CloudTrail enabled	Critical
Log file integrity validation	Medium
Multi-region trail configured	Medium
---
Quick Start
1. Clone the repo
```bash
git clone https://github.com/YOUR-USERNAME/cloud-misconfiguration-scanner
cd cloud-misconfiguration-scanner
```
2. Install dependencies
```bash
pip install -r requirements.txt
```
3. Run in demo mode (no AWS account needed)
```bash
python main.py
```
4. Run against a live AWS account
```bash
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=eu-west-2

python main.py
```
---
Example Output
```
========================================
  AWS MISCONFIGURATION SCAN — RESULTS
  [DEMO MODE — sample data]
========================================
Overall Risk : Critical
Total Checks : 15
Failed       : 10
Passed       : 5
----------------------------------------
[Critical] S3           Public Bucket Access
[Critical] IAM          Root Account MFA
[Critical] EC2          Security Group — SSH Open to World
[Critical] EC2          Security Group — RDP Open to World
[High    ] S3           Server-Side Encryption
[High    ] IAM          Access Keys Rotation
[High    ] IAM          Overprivileged Policies
[Medium  ] IAM          Console Users MFA
[Medium  ] EC2          EBS Volume Encryption
[Medium  ] CloudTrail   CloudTrail Log Validation
========================================
```
A full markdown report is saved automatically to `sample_output/`.
See a full sample report here
---
How It Works
```
AWS Credentials Present?
        ↓
   YES → boto3 connects to live AWS account
   NO  → Demo mode loads realistic sample findings
        ↓
Checks run across IAM / S3 / EC2 / CloudTrail
        ↓
Findings sorted by severity (Critical → Low)
        ↓
Markdown report saved to sample_output/
```
---
Real-World Context
These checks map directly to common findings in real AWS security assessments:
Public S3 buckets — responsible for some of the largest data breaches in history
No root MFA — complete account takeover if root credentials are compromised
SSH/RDP open to world — top vector for ransomware and cryptomining attacks
Stale access keys — often found in code repos, leading to full account compromise
No CloudTrail — means an attacker can operate undetected with no audit trail
---
Project Structure
```
cloud-misconfiguration-scanner/
├── main.py                  # Core scanner
├── requirements.txt         # Dependencies (boto3)
├── .gitignore               # Excludes AWS credentials
├── sample_output/
│   └── report.md            # Example scan report
└── README.md
```
---
Author: Ashish Mukherjee

Disclaimer
This tool is for authorised security assessments and educational purposes only. Never run against AWS accounts you do not own or have explicit written permission to test.
