# IAM Misconfiguration Detection Framework

A Python tool for automatically detecting AWS IAM misconfigurations that can lead to privilege escalation. Built as part of an MSc Cyber Security project at the University of Chester, where I simulated real-world IAM attacks in an isolated lab environment and then built this tool to detect them..

## What it does 

IAM misconfigurations are one of the most common causes of AWS breaches. This tool scans your AWS account and flags three high-severity issues:

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

Read-only access only — the script never modifies anything. Minimum permissions needed:
- `iam:ListUsers`
- `iam:GetUserPolicy`
- `iam:ListUserPolicies`
- `iam:ListAttachedUserPolicies`
- `iam:GetPolicyVersion`
- `iam:ListRoles`
- `iam:ListAttachedRolePolicies`
- `sts:GetCallerIdentity`

## Sample Output

`iam_report.json` in this repo contains real output from a scan of the lab environment used during the attack simulation phase.

## Ethical Notice

Only use this against AWS accounts you own or have explicit written permission to test. All development and testing was done in isolated student lab accounts with no connection to production systems.

## Author

Akindele Fanami — MSc Cyber Security, University of Chester (2026)
