"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         IAM Misconfiguration Detection Framework — AWS Module               ║
║         Hybrid Cloud Pentesting Project                                     ║
║         Module: WB7103/WB7104 | University of Chester                      ║
║         Author: [Akindele Fanami] | [2418178]                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

DESCRIPTION:
    Connects to AWS IAM and automatically detects misconfigurations
    corresponding to three attack patterns demonstrated in the lab:

    Check 1 — Unrestricted iam:PassRole
        Detects IAM users or roles holding iam:PassRole on Resource: *
        Corresponds to: Attack Pattern 1 (iam:PassRole Abuse)

    Check 2 — Wildcard IAM Policies
        Detects IAM policies granting iam:* or * on Resource: *
        Corresponds to: Attack Pattern 2 (Wildcard IAM Policies)

    Check 3 — Role Chaining Paths
        Detects roles whose trust policies allow other roles to assume them,
        creating potential privilege escalation chains
        Corresponds to: Attack Pattern 3 (Role Chaining)

USAGE:
    python3 iam_detector.py

REQUIREMENTS:
    pip3 install boto3
    AWS credentials configured via: aws configure

OUTPUT:
    Prints JSON findings to terminal and saves to iam_report.json
"""

import boto3
import json
from datetime import datetime


# ── Configuration ────────────────────────────────────────────────────────────

REGION = 'eu-west-2' 


# ── Initialise AWS clients ───────────────────────────────────────────────────

iam = boto3.client('iam', region_name=REGION)
sts = boto3.client('sts', region_name=REGION)

findings = []


# ── Helper Functions ─────────────────────────────────────────────────────────

def normalise_to_list(value):
    """Ensure a value is always a list, even if it's a single string."""
    if isinstance(value, str):
        return [value]
    if value is None:
        return []
    return value


def add_finding(check, severity, entity_type, entity_name, detail, mitre, stride):
    """Add a finding to the findings list."""
    findings.append({
        'check': check,
        'severity': severity,
        'entity_type': entity_type,
        'entity_name': entity_name,
        'detail': detail,
        'mitre_attack': mitre,
        'stride_category': stride
    })


# ── CHECK 1: Unrestricted iam:PassRole ───────────────────────────────────────

def check_passrole(policy_document, entity_name, entity_type):
    """
    Check a policy document for unrestricted iam:PassRole.

    iam:PassRole allows a principal to hand an IAM role to an AWS service
    (e.g. EC2). When granted on Resource: *, the principal can pass ANY role —
    including admin roles — enabling privilege escalation via EC2 metadata.
    """
    for statement in policy_document.get('Statement', []):
        if statement.get('Effect') != 'Allow':
            continue

        actions = normalise_to_list(statement.get('Action', []))
        resources = normalise_to_list(statement.get('Resource', []))

        # Flag if iam:PassRole (or a wildcard covering it) applies to all resources
        passrole_present = (
            'iam:PassRole' in actions or
            'iam:*' in actions or
            '*' in actions
        )

        if passrole_present and '*' in resources:
            add_finding(
                check='Unrestricted iam:PassRole',
                severity='CRITICAL',
                entity_type=entity_type,
                entity_name=entity_name,
                detail=(
                    f'iam:PassRole granted on Resource: * via action(s) {actions}. '
                    f'Allows passing any IAM role to any AWS service. '
                    f'Demonstrated exploit: attach admin role to EC2 and retrieve '
                    f'credentials via Instance Metadata Service.'
                ),
                mitre='T1078 (Valid Accounts) / T1548 (Abuse Elevation Control)',
                stride='Elevation of Privilege'
            )


# ── CHECK 2: Wildcard IAM Policies ───────────────────────────────────────────

def check_wildcard(policy_document, entity_name, entity_type):
    """
    Check a policy document for wildcard IAM actions on all resources.

    A policy granting iam:* or * on Resource: * gives full IAM control,
    allowing the principal to modify their own permissions, create admin
    users, or delete audit logs.
    """
    for statement in policy_document.get('Statement', []):
        if statement.get('Effect') != 'Allow':
            continue

        actions = normalise_to_list(statement.get('Action', []))
        resources = normalise_to_list(statement.get('Resource', []))

        wildcard_action = 'iam:*' in actions or '*' in actions

        if wildcard_action and '*' in resources:
            add_finding(
                check='Wildcard IAM Policy',
                severity='CRITICAL',
                entity_type=entity_type,
                entity_name=entity_name,
                detail=(
                    f'Action(s) {actions} granted on Resource: *. '
                    f'Grants full IAM control — principal can attach AdministratorAccess '
                    f'to themselves in a single API call. '
                    f'Demonstrated exploit: aws iam attach-user-policy with AdministratorAccess.'
                ),
                mitre='T1484 (Domain Policy Modification)',
                stride='Elevation of Privilege, Tampering'
            )


# ── CHECK 3: Role Chaining Paths ─────────────────────────────────────────────

def check_role_chaining(roles):
    """
    Detect role chaining paths by analysing trust policies.

    Builds a map of which roles can assume which other roles.
    Flags any role whose trust policy allows another role as principal —
    creating a potential multi-hop privilege escalation chain.
    """
    # Build role name to ARN map
    role_map = {role['RoleName']: role['Arn'] for role in roles}

    for role in roles:
        role_name = role['RoleName']
        trust_doc = role['AssumeRolePolicyDocument']

        for statement in trust_doc.get('Statement', []):
            if statement.get('Effect') != 'Allow':
                continue

            principal = statement.get('Principal', {})

            # Principal can be a string, dict, or list
            if isinstance(principal, str):
                aws_principals = [principal]
            elif isinstance(principal, dict):
                aws_principals = normalise_to_list(principal.get('AWS', []))
            else:
                aws_principals = principal

            for p in aws_principals:
                if ':role/' in str(p):
                    assuming_role = str(p).split(':role/')[-1]

                    # Check if the assuming role has a high-privilege policy
                    try:
                        attached = iam.list_attached_role_policies(
                            RoleName=role_name
                        )['AttachedPolicies']
                        policy_names = [p['PolicyName'] for p in attached]
                        high_priv = any(
                            name in ['AdministratorAccess', 'PowerUserAccess']
                            for name in policy_names
                        )
                    except Exception:
                        high_priv = False
                        policy_names = ['Unknown']

                    severity = 'CRITICAL' if high_priv else 'HIGH'
                    detail = (
                        f'Role {assuming_role} is trusted to assume {role_name}. '
                        f'{role_name} holds: {policy_names}. '
                    )
                    if high_priv:
                        detail += (
                            f'CRITICAL: {role_name} has AdministratorAccess — '
                            f'this chain leads to full admin privileges.'
                        )
                    else:
                        detail += (
                            f'Investigate whether this chain can reach a higher-privilege role.'
                        )

                    add_finding(
                        check='Role Chaining Path',
                        severity=severity,
                        entity_type='IAM Role',
                        entity_name=role_name,
                        detail=detail,
                        mitre='T1548 (Abuse Elevation Control Mechanism)',
                        stride='Elevation of Privilege'
                    )


# ── Main Scanning Logic ───────────────────────────────────────────────────────

def run_scan():
    print("=" * 65)
    print("  IAM Misconfiguration Detection Framework")
    print("  Hybrid Cloud Pentesting Project — AWS Module")
    print("=" * 65)

    # Get account ID
    account_id = sts.get_caller_identity()['Account']
    caller = sts.get_caller_identity()['Arn']
    print(f"\n[*] Account:  {account_id}")
    print(f"[*] Identity: {caller}")
    print(f"[*] Region:   {REGION}")
    print(f"[*] Started:  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

    # ── Check 1: PassRole ──────────────────────────────────────────
    print("[CHECK 1] Scanning for unrestricted iam:PassRole...")
    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        # Inline policies
        inline = iam.list_user_policies(UserName=username)['PolicyNames']
        for policy_name in inline:
            doc = iam.get_user_policy(
                UserName=username,
                PolicyName=policy_name
            )['PolicyDocument']
            check_passrole(doc, username, 'IAM User')

        # Attached managed policies
        attached = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        for policy in attached:
            versions = iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']
            version_id = versions['DefaultVersionId']
            doc = iam.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=version_id
            )['PolicyVersion']['Document']
            check_passrole(doc, username, 'IAM User')

    print(f"         → {len(findings)} finding(s) detected\n")
    passrole_count = len(findings)

    # ── Check 2: Wildcard Policies ────────────────────────────────
    print("[CHECK 2] Scanning for wildcard IAM policies...")

    for user in users:
        username = user['UserName']
        inline = iam.list_user_policies(UserName=username)['PolicyNames']
        for policy_name in inline:
            doc = iam.get_user_policy(
                UserName=username,
                PolicyName=policy_name
            )['PolicyDocument']
            check_wildcard(doc, username, 'IAM User')

    print(f"         → {len(findings) - passrole_count} new finding(s) detected\n")
    wildcard_count = len(findings)

    # ── Check 3: Role Chaining ────────────────────────────────────
    print("[CHECK 3] Scanning for role chaining paths...")
    roles = iam.list_roles()['Roles']
    check_role_chaining(roles)
    print(f"         → {len(findings) - wildcard_count} new finding(s) detected\n")

    # ── Output Report ─────────────────────────────────────────────
    report = {
        'report_metadata': {
            'framework': 'IAM Misconfiguration Detection Framework',
            'project': 'Hybrid Cloud Pentesting — WB7103/WB7104',
            'account_id': account_id,
            'region': REGION,
            'scan_timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'total_findings': len(findings),
            'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
            'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
        },
        'findings': findings
    }

    print("=" * 65)
    print(f"  SCAN COMPLETE — {len(findings)} FINDING(S)")
    print(f"  CRITICAL: {report['report_metadata']['critical']}  |  HIGH: {report['report_metadata']['high']}")
    print("=" * 65)
    print()
    print(json.dumps(report, indent=2))

    # Save report
    report_file = 'iam_report.json'
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n[*] Full report saved to: {report_file}")


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    run_scan()
