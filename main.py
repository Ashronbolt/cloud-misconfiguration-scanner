"""
AWS Cloud Misconfiguration Scanner
Author: Security Portfolio Project
Description: Scans AWS environment for common security misconfigurations
             across IAM, S3, EC2, and CloudTrail. Supports demo mode
             when no AWS account is available.
"""

import json
import os
import sys
from datetime import datetime

DEMO_MODE = not bool(os.environ.get("AWS_ACCESS_KEY_ID"))


# --------------------------------------------------------------------------
# DEMO DATA — realistic findings for portfolio demonstration
# --------------------------------------------------------------------------

DEMO_FINDINGS = [
    {
        "service": "S3",
        "check": "Public Bucket Access",
        "resource": "s3://company-backup-prod",
        "status": "FAIL",
        "severity": "Critical",
        "detail": "Bucket has public read access enabled. Sensitive data may be exposed to the internet.",
        "remediation": "Enable S3 Block Public Access at bucket and account level. Review bucket policy and ACLs."
    },
    {
        "service": "S3",
        "check": "Server-Side Encryption",
        "resource": "s3://company-backup-prod",
        "status": "FAIL",
        "severity": "High",
        "detail": "Bucket does not have default server-side encryption enabled.",
        "remediation": "Enable AES-256 or AWS KMS encryption as the default encryption for the bucket."
    },
    {
        "service": "S3",
        "check": "Server-Side Encryption",
        "resource": "s3://static-assets-web",
        "status": "PASS",
        "severity": "High",
        "detail": "Bucket has AES-256 encryption enabled.",
        "remediation": None
    },
    {
        "service": "IAM",
        "check": "Root Account MFA",
        "resource": "arn:aws:iam::123456789012:root",
        "status": "FAIL",
        "severity": "Critical",
        "detail": "Root account does not have MFA enabled. Root account has unrestricted access to all AWS services.",
        "remediation": "Enable MFA on the root account immediately. Use a hardware MFA device where possible."
    },
    {
        "service": "IAM",
        "check": "Access Keys Rotation",
        "resource": "arn:aws:iam::123456789012:user/dev-deploy",
        "status": "FAIL",
        "severity": "High",
        "detail": "IAM user access key has not been rotated in 142 days (threshold: 90 days).",
        "remediation": "Rotate access keys every 90 days. Consider using IAM roles instead of long-lived access keys."
    },
    {
        "service": "IAM",
        "check": "Overprivileged Policies",
        "resource": "arn:aws:iam::123456789012:user/analyst-john",
        "status": "FAIL",
        "severity": "High",
        "detail": "User has AdministratorAccess policy attached. Full admin access granted to non-admin user.",
        "remediation": "Apply principle of least privilege. Replace AdministratorAccess with scoped policies."
    },
    {
        "service": "IAM",
        "check": "Console Users MFA",
        "resource": "arn:aws:iam::123456789012:user/analyst-john",
        "status": "FAIL",
        "severity": "Medium",
        "detail": "IAM user with console access does not have MFA enabled.",
        "remediation": "Enforce MFA for all IAM users with console access via an IAM policy condition."
    },
    {
        "service": "IAM",
        "check": "Console Users MFA",
        "resource": "arn:aws:iam::123456789012:user/dev-deploy",
        "status": "PASS",
        "severity": "Medium",
        "detail": "MFA is enabled for this user.",
        "remediation": None
    },
    {
        "service": "EC2",
        "check": "Security Group — SSH Open to World",
        "resource": "sg-0abc123def456 (prod-web-sg)",
        "status": "FAIL",
        "severity": "Critical",
        "detail": "Security group allows SSH (port 22) inbound from 0.0.0.0/0. Any IP can attempt SSH access.",
        "remediation": "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager instead."
    },
    {
        "service": "EC2",
        "check": "Security Group — RDP Open to World",
        "resource": "sg-0abc123def456 (prod-web-sg)",
        "status": "FAIL",
        "severity": "Critical",
        "detail": "Security group allows RDP (port 3389) inbound from 0.0.0.0/0.",
        "remediation": "Restrict RDP to known IP ranges or use a VPN/bastion host architecture."
    },
    {
        "service": "EC2",
        "check": "EBS Volume Encryption",
        "resource": "vol-0abc123def456789 (prod-web-01)",
        "status": "FAIL",
        "severity": "Medium",
        "detail": "EBS volume is not encrypted. Data at rest is unprotected.",
        "remediation": "Enable EBS encryption by default in account settings. Migrate existing volumes to encrypted copies."
    },
    {
        "service": "EC2",
        "check": "IMDSv2 Enforced",
        "resource": "i-0abc123def456789 (prod-web-01)",
        "status": "FAIL",
        "severity": "Medium",
        "detail": "Instance metadata service v1 (IMDSv1) is enabled. Vulnerable to SSRF-based metadata attacks.",
        "remediation": "Enforce IMDSv2 on all EC2 instances to mitigate SSRF attacks targeting instance metadata."
    },
    {
        "service": "CloudTrail",
        "check": "CloudTrail Enabled",
        "resource": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/mgmt-trail",
        "status": "PASS",
        "severity": "Critical",
        "detail": "CloudTrail is enabled and logging to S3.",
        "remediation": None
    },
    {
        "service": "CloudTrail",
        "check": "CloudTrail Log Validation",
        "resource": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/mgmt-trail",
        "status": "FAIL",
        "severity": "Medium",
        "detail": "Log file integrity validation is not enabled. Logs could be tampered with without detection.",
        "remediation": "Enable log file validation on CloudTrail to detect any tampering with log files."
    },
    {
        "service": "CloudTrail",
        "check": "Multi-Region Trail",
        "resource": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/mgmt-trail",
        "status": "FAIL",
        "severity": "Medium",
        "detail": "CloudTrail is not configured as a multi-region trail. Activity in other regions is not logged.",
        "remediation": "Configure CloudTrail as a multi-region trail to capture all API activity across all regions."
    },
]


# --------------------------------------------------------------------------
# LIVE AWS SCANNING (requires boto3 + credentials)
# --------------------------------------------------------------------------

def scan_live_aws() -> list:
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed. Run: pip install boto3")
        sys.exit(1)

    findings = []

    # --- S3 ---
    print("[*] Scanning S3 buckets...")
    s3 = boto3.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            resource = f"s3://{name}"

            # Public access check
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                public = any(
                    grant["Grantee"].get("URI", "") == "http://acs.amazonaws.com/groups/global/AllUsers"
                    for grant in acl.get("Grants", [])
                )
                findings.append({
                    "service": "S3", "check": "Public Bucket Access", "resource": resource,
                    "status": "FAIL" if public else "PASS", "severity": "Critical",
                    "detail": "Bucket has public read access." if public else "Bucket is private.",
                    "remediation": "Enable S3 Block Public Access." if public else None
                })
            except Exception as e:
                findings.append({"service": "S3", "check": "Public Bucket Access", "resource": resource,
                                  "status": "ERROR", "severity": "Critical", "detail": str(e), "remediation": None})

            # Encryption check
            try:
                s3.get_bucket_encryption(Bucket=name)
                findings.append({
                    "service": "S3", "check": "Server-Side Encryption", "resource": resource,
                    "status": "PASS", "severity": "High", "detail": "Encryption enabled.", "remediation": None
                })
            except s3.exceptions.ClientError:
                findings.append({
                    "service": "S3", "check": "Server-Side Encryption", "resource": resource,
                    "status": "FAIL", "severity": "High",
                    "detail": "No default encryption configured.",
                    "remediation": "Enable AES-256 or KMS encryption as default."
                })
    except Exception as e:
        print(f"[!] S3 scan error: {e}")

    # --- IAM ---
    print("[*] Scanning IAM...")
    iam = boto3.client("iam")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_active = summary.get("AccountMFAEnabled", 0)
        findings.append({
            "service": "IAM", "check": "Root Account MFA",
            "resource": "arn:aws:iam:::root",
            "status": "PASS" if mfa_active else "FAIL",
            "severity": "Critical",
            "detail": "Root MFA enabled." if mfa_active else "Root account has no MFA.",
            "remediation": None if mfa_active else "Enable MFA on root account immediately."
        })

        users = iam.list_users()["Users"]
        for user in users:
            uname = user["UserName"]
            arn = user["Arn"]

            # MFA check
            mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
            has_mfa = len(mfa_devices) > 0
            findings.append({
                "service": "IAM", "check": "Console Users MFA", "resource": arn,
                "status": "PASS" if has_mfa else "FAIL", "severity": "Medium",
                "detail": "MFA enabled." if has_mfa else "No MFA on console user.",
                "remediation": None if has_mfa else "Enforce MFA for all console users."
            })

            # Access key age
            keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
            for key in keys:
                age = (datetime.utcnow() - key["CreateDate"].replace(tzinfo=None)).days
                findings.append({
                    "service": "IAM", "check": "Access Keys Rotation", "resource": arn,
                    "status": "PASS" if age <= 90 else "FAIL", "severity": "High",
                    "detail": f"Access key age: {age} days.",
                    "remediation": None if age <= 90 else "Rotate access keys every 90 days."
                })
    except Exception as e:
        print(f"[!] IAM scan error: {e}")

    # --- EC2 Security Groups ---
    print("[*] Scanning EC2 security groups...")
    ec2 = boto3.client("ec2")
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "unnamed")
            resource = f"{sg_id} ({sg_name})"
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        if from_port == 22:
                            findings.append({
                                "service": "EC2", "check": "Security Group — SSH Open to World",
                                "resource": resource, "status": "FAIL", "severity": "Critical",
                                "detail": "SSH open to 0.0.0.0/0.",
                                "remediation": "Restrict SSH to known IPs or use SSM Session Manager."
                            })
                        if from_port == 3389:
                            findings.append({
                                "service": "EC2", "check": "Security Group — RDP Open to World",
                                "resource": resource, "status": "FAIL", "severity": "Critical",
                                "detail": "RDP open to 0.0.0.0/0.",
                                "remediation": "Restrict RDP to known IPs or use VPN."
                            })
    except Exception as e:
        print(f"[!] EC2 scan error: {e}")

    # --- CloudTrail ---
    print("[*] Scanning CloudTrail...")
    ct = boto3.client("cloudtrail")
    try:
        trails = ct.describe_trails()["trailList"]
        if not trails:
            findings.append({
                "service": "CloudTrail", "check": "CloudTrail Enabled",
                "resource": "N/A", "status": "FAIL", "severity": "Critical",
                "detail": "No CloudTrail trails found.",
                "remediation": "Enable CloudTrail in all regions immediately."
            })
        for trail in trails:
            arn = trail["TrailARN"]
            findings.append({
                "service": "CloudTrail", "check": "CloudTrail Enabled",
                "resource": arn, "status": "PASS", "severity": "Critical",
                "detail": "CloudTrail is enabled.", "remediation": None
            })
            log_validation = trail.get("LogFileValidationEnabled", False)
            findings.append({
                "service": "CloudTrail", "check": "CloudTrail Log Validation",
                "resource": arn,
                "status": "PASS" if log_validation else "FAIL", "severity": "Medium",
                "detail": "Log validation enabled." if log_validation else "Log file validation not enabled.",
                "remediation": None if log_validation else "Enable log file integrity validation."
            })
    except Exception as e:
        print(f"[!] CloudTrail scan error: {e}")

    return findings


# --------------------------------------------------------------------------
# REPORT GENERATION
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def calculate_summary(findings: list) -> dict:
    fails = [f for f in findings if f["status"] == "FAIL"]
    passes = [f for f in findings if f["status"] == "PASS"]
    by_severity = {}
    for f in fails:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    if by_severity.get("Critical", 0) > 0:
        overall = "Critical"
    elif by_severity.get("High", 0) > 0:
        overall = "High"
    elif by_severity.get("Medium", 0) > 0:
        overall = "Medium"
    else:
        overall = "Low"

    return {
        "total": len(findings),
        "failed": len(fails),
        "passed": len(passes),
        "by_severity": by_severity,
        "overall_risk": overall
    }


def save_report(findings: list, output_dir: str = "sample_output") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"scan_report_{timestamp}.md")
    summary = calculate_summary(findings)

    lines = []
    lines.append("# AWS Cloud Misconfiguration Scan Report")
    lines.append(f"\n**Generated:** {datetime.now().strftime('%d %B %Y %H:%M')}")
    lines.append(f"\n**Mode:** {'DEMO' if DEMO_MODE else 'LIVE AWS SCAN'}")
    lines.append(f"\n**Overall Risk Rating:** `{summary['overall_risk']}`\n")
    lines.append("---\n")
    lines.append("## Summary\n")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Checks | {summary['total']} |")
    lines.append(f"| Failed | {summary['failed']} |")
    lines.append(f"| Passed | {summary['passed']} |")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = summary["by_severity"].get(sev, 0)
        if count:
            lines.append(f"| {sev} Findings | {count} |")
    lines.append("\n---\n")
    lines.append("## Findings\n")

    fails = sorted(
        [f for f in findings if f["status"] == "FAIL"],
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 4)
    )
    passes = [f for f in findings if f["status"] == "PASS"]

    for f in fails:
        lines.append(f"### ❌ [{f['severity']}] {f['service']} — {f['check']}")
        lines.append(f"\n**Resource:** `{f['resource']}`")
        lines.append(f"\n**Detail:** {f['detail']}")
        lines.append(f"\n**Remediation:** {f['remediation']}\n")

    lines.append("\n---\n")
    lines.append("## Passed Checks\n")
    for f in passes:
        lines.append(f"- ✅ **{f['service']}** — {f['check']} (`{f['resource']}`)")

    lines.append("\n---")
    lines.append("*Report generated by AWS Cloud Misconfiguration Scanner*")

    with open(path, "w") as file:
        file.write("\n".join(lines))

    return path


def print_summary(findings: list):
    summary = calculate_summary(findings)
    print("\n========================================")
    print("  AWS MISCONFIGURATION SCAN — RESULTS")
    if DEMO_MODE:
        print("  [DEMO MODE — sample data]")
    print("========================================")
    print(f"Overall Risk : {summary['overall_risk']}")
    print(f"Total Checks : {summary['total']}")
    print(f"Failed       : {summary['failed']}")
    print(f"Passed       : {summary['passed']}")
    print("----------------------------------------")
    fails = sorted(
        [f for f in findings if f["status"] == "FAIL"],
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 4)
    )
    for f in fails:
        print(f"[{f['severity']:8}] {f['service']:12} {f['check']}")
    print("========================================\n")


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------

def main():
    print("=== AWS Cloud Misconfiguration Scanner ===")
    print("Security Portfolio Project\n")

    if DEMO_MODE:
        print("[i] No AWS credentials detected — running in DEMO MODE")
        print("[i] To run against a live AWS account, set:")
        print("    export AWS_ACCESS_KEY_ID=your-key")
        print("    export AWS_SECRET_ACCESS_KEY=your-secret")
        print("    export AWS_DEFAULT_REGION=eu-west-2\n")
        findings = DEMO_FINDINGS
    else:
        print("[i] AWS credentials detected — running LIVE SCAN\n")
        findings = scan_live_aws()

    print_summary(findings)
    report_path = save_report(findings)
    print(f"[+] Full report saved to: {report_path}")


if __name__ == "__main__":
    main()
