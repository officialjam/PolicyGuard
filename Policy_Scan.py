import os
import json
import gzip
import datetime as dt
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError


# ----------------------------
# YOUR SETTINGS (wired in)
# ----------------------------

DEFAULT_REPORT_BUCKET = "policy-scan-reports"
DEFAULT_REPORT_PREFIX = "reports/"           # policy-scan-reports to your S3 bucket name
DEFAULT_MAX_ITEMS = 200                     # cap while learning (set env MAX_ITEMS to override)


# ----------------------------
# Models
# ----------------------------

@dataclass
class PolicyItem:
    resource_type: str
    resource_id: str
    name: str
    document: Dict[str, Any]
    metadata: Dict[str, Any]


@dataclass
class Finding:
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    title: str
    resource_type: str
    resource_id: str
    resource_name: str
    evidence: Dict[str, Any]
    recommendation: str
    remediation_hint: str


# ----------------------------
# Helpers
# ----------------------------

def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def ensure_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def normalize_policy_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(doc) if isinstance(doc, dict) else {}
    out["Statement"] = ensure_list(out.get("Statement", []))
    return out

def statement_actions(stmt: Dict[str, Any]) -> List[str]:
    return [str(a) for a in ensure_list(stmt.get("Action"))]

def statement_resources(stmt: Dict[str, Any]) -> List[str]:
    return [str(r) for r in ensure_list(stmt.get("Resource"))]

def is_allow(stmt: Dict[str, Any]) -> bool:
    return str(stmt.get("Effect", "")).lower() == "allow"

def principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for _, v in principal.items():
            if v == "*":
                return True
            if isinstance(v, list) and any(item == "*" for item in v):
                return True
    return False

def has_restrictive_condition(stmt: Dict[str, Any]) -> bool:
    cond = stmt.get("Condition")
    if not isinstance(cond, dict):
        return False
    cond_str = json.dumps(cond, default=str).lower()
    good_markers = [
        "aws:sourcearn",
        "aws:sourceaccount",
        "aws:principalorgid",
        "aws:sourcevpce",
        "aws:sourceip",
        "sts:externalid",
        "aws:principalarn",
    ]
    return any(m in cond_str for m in good_markers)


# ----------------------------
# Collectors (IAM MVP)
# ----------------------------

def collect_iam_managed_policies(iam, max_items: Optional[int]) -> List[PolicyItem]:
    items: List[PolicyItem] = []
    paginator = iam.get_paginator("list_policies")

    count = 0
    for page in paginator.paginate(Scope="Local"):  # customer-managed only
        for p in page.get("Policies", []):
            if max_items is not None and count >= max_items:
                return items
            count += 1

            arn = p["Arn"]
            name = p["PolicyName"]
            default_ver = p["DefaultVersionId"]

            ver = iam.get_policy_version(PolicyArn=arn, VersionId=default_ver)
            doc = normalize_policy_doc(ver["PolicyVersion"]["Document"])

            items.append(
                PolicyItem(
                    resource_type="iam_managed_policy",
                    resource_id=arn,
                    name=name,
                    document=doc,
                    metadata={
                        "default_version": default_ver,
                        "attachment_count": p.get("AttachmentCount", 0),
                        "update_date": str(p.get("UpdateDate", "")),
                    },
                )
            )
    return items


def collect_iam_role_trust_policies(iam, max_items: Optional[int]) -> List[PolicyItem]:
    items: List[PolicyItem] = []
    paginator = iam.get_paginator("list_roles")

    count = 0
    for page in paginator.paginate():
        for r in page.get("Roles", []):
            if max_items is not None and count >= max_items:
                return items
            count += 1

            role_name = r["RoleName"]
            role_arn = r["Arn"]
            trust_doc = normalize_policy_doc(r.get("AssumeRolePolicyDocument", {}))

            items.append(
                PolicyItem(
                    resource_type="iam_role_trust",
                    resource_id=role_arn,
                    name=role_name,
                    document=trust_doc,
                    metadata={
                        "create_date": str(r.get("CreateDate", "")),
                        "max_session_duration": r.get("MaxSessionDuration", None),
                    },
                )
            )
    return items


# ----------------------------
# Rules (MVP)
# ----------------------------

SENSITIVE_WILDCARDS = {"iam:*", "kms:*", "sts:*", "*:*"}

def rule_allow_star_star(item: PolicyItem) -> List[Finding]:
    findings: List[Finding] = []
    for idx, stmt in enumerate(item.document.get("Statement", [])):
        if not is_allow(stmt):
            continue
        actions = [a.lower() for a in statement_actions(stmt)]
        resources = statement_resources(stmt)
        if "*" in actions and "*" in resources:
            findings.append(Finding(
                severity="CRITICAL",
                title="Allow * action on * resource",
                resource_type=item.resource_type,
                resource_id=item.resource_id,
                resource_name=item.name,
                evidence={"statement_index": idx, "statement": stmt},
                recommendation="Scope permissions to specific actions and specific ARNs; avoid blanket admin grants.",
                remediation_hint="Replace Action:\"*\" and Resource:\"*\" with least-privilege values; add Conditions if needed."
            ))
    return findings

def rule_sensitive_service_wildcards(item: PolicyItem) -> List[Finding]:
    findings: List[Finding] = []
    for idx, stmt in enumerate(item.document.get("Statement", [])):
        if not is_allow(stmt):
            continue
        actions = [a.lower() for a in statement_actions(stmt)]
        if any(a in SENSITIVE_WILDCARDS for a in actions):
            findings.append(Finding(
                severity="HIGH",
                title="Sensitive service wildcard permissions",
                resource_type=item.resource_type,
                resource_id=item.resource_id,
                resource_name=item.name,
                evidence={"statement_index": idx, "actions": statement_actions(stmt), "statement": stmt},
                recommendation="Avoid wildcard permissions for IAM/KMS/STS; they often enable privilege escalation.",
                remediation_hint="Replace service wildcards with explicit actions; restrict Resource to specific ARNs."
            ))
    return findings

def rule_iam_passrole_unrestricted(item: PolicyItem) -> List[Finding]:
    if item.resource_type != "iam_managed_policy":
        return []
    findings: List[Finding] = []
    for idx, stmt in enumerate(item.document.get("Statement", [])):
        if not is_allow(stmt):
            continue
        actions = [a.lower() for a in statement_actions(stmt)]
        if "iam:passrole" in actions:
            resources = statement_resources(stmt)
            if "*" in resources:
                findings.append(Finding(
                    severity="HIGH",
                    title="iam:PassRole is unrestricted",
                    resource_type=item.resource_type,
                    resource_id=item.resource_id,
                    resource_name=item.name,
                    evidence={"statement_index": idx, "statement": stmt},
                    recommendation="Restrict PassRole to approved role ARNs and add conditions (iam:PassedToService).",
                    remediation_hint="Set Resource to specific role ARNs; add Condition iam:PassedToService where applicable."
                ))
    return findings

def rule_trust_policy_public_principal(item: PolicyItem) -> List[Finding]:
    if item.resource_type != "iam_role_trust":
        return []
    findings: List[Finding] = []
    for idx, stmt in enumerate(item.document.get("Statement", [])):
        if not is_allow(stmt):
            continue
        principal = stmt.get("Principal")
        if principal_is_wildcard(principal):
            findings.append(Finding(
                severity="CRITICAL",
                title="Role trust policy allows wildcard principal",
                resource_type=item.resource_type,
                resource_id=item.resource_id,
                resource_name=item.name,
                evidence={"statement_index": idx, "principal": principal, "statement": stmt},
                recommendation="Limit who can assume this role. Wildcard trust is almost always unsafe.",
                remediation_hint="Replace wildcard principal with specific account/role ARNs; add aws:PrincipalOrgID or sts:ExternalId conditions."
            ))
    return findings

def rule_trust_cross_account_missing_condition(item: PolicyItem) -> List[Finding]:
    if item.resource_type != "iam_role_trust":
        return []
    findings: List[Finding] = []
    for idx, stmt in enumerate(item.document.get("Statement", [])):
        if not is_allow(stmt):
            continue
        principal = stmt.get("Principal")
        if isinstance(principal, dict) and "AWS" in principal:
            if not has_restrictive_condition(stmt):
                findings.append(Finding(
                    severity="MEDIUM",
                    title="Cross-account trust without restrictive conditions",
                    resource_type=item.resource_type,
                    resource_id=item.resource_id,
                    resource_name=item.name,
                    evidence={"statement_index": idx, "principal": principal, "condition": stmt.get("Condition"), "statement": stmt},
                    recommendation="When trusting external principals, enforce conditions to reduce abuse risk.",
                    remediation_hint="Add aws:PrincipalOrgID, sts:ExternalId, or aws:SourceArn/aws:SourceAccount depending on your integration."
                ))
    return findings

RULES = [
    rule_allow_star_star,
    rule_sensitive_service_wildcards,
    rule_iam_passrole_unrestricted,
    rule_trust_policy_public_principal,
    rule_trust_cross_account_missing_condition,
]


# ----------------------------
# Reporter (S3 + logs)
# ----------------------------

def put_report_to_s3(s3, bucket: str, key: str, report: Dict[str, Any]) -> None:
    raw = json.dumps(report, indent=2, default=str, sort_keys=True).encode("utf-8")
    gz = gzip.compress(raw)

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=gz,
        ContentType="application/json",
        ContentEncoding="gzip",
    )


# ----------------------------
# Lambda Handler
# ----------------------------

def lambda_handler(event, context):
    # Allow env overrides, but defaults will work immediately
    report_bucket = os.environ.get("REPORT_BUCKET", DEFAULT_REPORT_BUCKET)
    report_prefix = os.environ.get("REPORT_PREFIX", DEFAULT_REPORT_PREFIX)

    max_items_env = os.environ.get("MAX_ITEMS")
    max_items = int(max_items_env) if max_items_env else DEFAULT_MAX_ITEMS

    iam = boto3.client("iam")
    s3 = boto3.client("s3")
    sts = boto3.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    generated_at = utc_now_iso()

    # 1) Collect
    policy_items: List[PolicyItem] = []
    policy_items.extend(collect_iam_managed_policies(iam, max_items=max_items))
    policy_items.extend(collect_iam_role_trust_policies(iam, max_items=max_items))

    # 2) Evaluate
    findings: List[Finding] = []
    for item in policy_items:
        for rule in RULES:
            try:
                findings.extend(rule(item))
            except Exception as e:
                # keep scan running even if a rule hits a weird edge case
                findings.append(Finding(
                    severity="LOW",
                    title="Rule execution error",
                    resource_type=item.resource_type,
                    resource_id=item.resource_id,
                    resource_name=item.name,
                    evidence={"rule": rule.__name__, "error": str(e)},
                    recommendation="Harden the rule against unexpected policy shapes.",
                    remediation_hint="Add defensive parsing for Action/Resource/Principal formats."
                ))

    # 3) Summarize
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    report = {
        "generated_at": generated_at,
        "account_id": account_id,
        "bucket": report_bucket,
        "prefix": report_prefix,
        "scanned": {
            "items_count": len(policy_items),
            "types": {
                "iam_managed_policy": sum(1 for x in policy_items if x.resource_type == "iam_managed_policy"),
                "iam_role_trust": sum(1 for x in policy_items if x.resource_type == "iam_role_trust"),
            }
        },
        "summary": {
            "finding_count": len(findings),
            "severity_counts": severity_counts,
        },
        "findings": [asdict(f) for f in findings],
    }

    # 4) Write to S3
    date_path = dt.datetime.now(dt.timezone.utc).strftime("%Y/%m/%d")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%H%M%S")
    key = f"{report_prefix.rstrip('/')}/{account_id}/{date_path}/policy-scan-{timestamp}Z.json.gz"

    try:
        put_report_to_s3(s3, report_bucket, key, report)
    except ClientError as e:
        print("❌ Failed to write report to S3:", str(e))
        raise

    # 5) Log summary (CloudWatch)
    print("✅ Policy scan complete")
    print("Account:", account_id)
    print("Scanned items:", len(policy_items))
    print("Findings:", len(findings))
    print("Severity counts:", severity_counts)
    print("S3 report:", f"s3://{report_bucket}/{key}")

    return {
        "ok": True,
        "account_id": account_id,
        "scanned_items": len(policy_items),
        "findings": len(findings),
        "severity_counts": severity_counts,
        "s3_key": key,
        "bucket": report_bucket,
        "generated_at": generated_at,
    }
