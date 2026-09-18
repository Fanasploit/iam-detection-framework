# IAM Misconfiguration Detection Framework

A threat-model-driven Python detection framework for AWS IAM misconfigurations, developed as part of an MSc Cyber Security work-based project at the University of Chester (WB7103/WB7104).

## Project Overview

Cloud IAM misconfiguration is the leading cause of cloud security incidents. This framework automatically detects three high-severity IAM misconfigurations that were demonstrated through hands-on attack simulation in an isolated AWS lab environment:

| Attack Pattern | STRIDE | MITRE ATT&CK |
|---|---|---|
| iam:PassRole Abuse | Elevation of Privilege | T1078 / T1548 |
| Wildcard IAM Policies | Elevation of Privilege, Tampering | T1484 |
| Role Chaining | Elevation of Privilege | T1548 |

## Requirements

- Python 3
- AWS CLI configured with valid credentials (`aws configure`)
- Boto3

## Installation

```bash
git clone https://github.com/fanasploit/iam-detection-framework.git
cd iam-detection-framework
pip install -r requirements.txt
```

## Usage

```bash
python3 iam_detector.py
```

The script will:
1. Connect to your AWS account using configured credentials
2. Scan all IAM users, roles, and policies
3. Print findings to the terminal
4. Save a full JSON report to `iam_report.json`

## Required AWS Permissions

The script only makes read-only API calls. Deploy with a least-privilege role holding:
- `iam:ListUsers`
- `iam:GetUserPolicy`
- `iam:ListUserPolicies`
- `iam:ListAttachedUserPolicies`
- `iam:GetPolicyVersion`
- `iam:ListRoles`
- `iam:ListAttachedRolePolicies`
- `sts:GetCallerIdentity`

## Sample Output

See `iam_report.json` for a sample report generated against the lab environment.

## Ethical Notice

This framework is intended for use against AWS accounts you own or have explicit written authorisation to test. All development and testing was conducted in isolated student lab accounts with no connection to production systems.

## Author

Akin — MSc Cyber Security, University of Chester (2025/26)
