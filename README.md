# PolicyScan

**PolicyScan** is a serverless AWS security tool that automatically scans IAM policies and role trust relationships for risky access patterns, least-privilege violations, and cross-account exposure.

It runs as an AWS Lambda function on a scheduled Amazon EventBridge trigger and generates compressed JSON audit reports in Amazon S3 with actionable remediation guidance.

---

## Issues

Manual IAM reviews do not scale in environments with frequent role and policy changes. Over time, wildcard permissions, unrestricted `iam:PassRole`, and overly permissive trust relationships often persist unnoticed and increase the risk of privilege escalation or unintended cross-account access.

PolicyScan addresses this problem by providing a lightweight, scheduled mechanism to continuously evaluate IAM policies against security heuristics and generate actionable findings without modifying existing resources.

This project focuses on detection and reporting only; it does not modify IAM resources.

---

## Architecture overview

High-level flow:

```
EventBridge (schedule)
        ↓
    AWS Lambda
        ↓
IAM APIs (read-only)
        ↓
    Rule engine
        ↓
Amazon S3 (gzip JSON reports)

```

<img width="1137" height="332" alt="Screenshot 2026-02-07 at 16 47 37" src="https://github.com/user-attachments/assets/b7b82cd4-c96c-4d77-a8ad-3a6d2ef0900d" />


AWS services used:
- AWS Lambda  
- Amazon EventBridge  
- AWS Identity and Access Management (IAM)  
- Amazon S3  
- Amazon CloudWatch Logs  

---

## What PolicyScan checks

The current rule set identifies common high-risk IAM patterns, including:

- `Allow` permissions with `Action: "*"` and `Resource: "*"`
- Wildcard permissions for sensitive services (`iam:*`, `kms:*`, `sts:*`)
- Unrestricted `iam:PassRole`
- Role trust policies allowing wildcard principals
- Cross-account trust policies without restrictive conditions
- Admin-like wildcard action patterns

Each finding includes:
- Severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- Evidence (the exact policy statement)
- Recommendation
- Remediation hint

---

## Sample output

Each execution produces a gzip-compressed JSON report. Example:

```json
{
  "summary": {
    "finding_count": 3,
    "severity_counts": {
      "LOW": 0,
      "MEDIUM": 1,
      "HIGH": 1,
      "CRITICAL": 1
    }
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "title": "Role trust policy allows wildcard principal",
      "resource_type": "iam_role_trust",
      "resource_id": "arn:aws:iam::123456789012:role/example-role",
      "recommendation": "Restrict who can assume this role"
    }
  ]
}
```

A complete example is available in the `sample-output/` directory.

---

## Deployment instructions

### 1. Create an S3 bucket

Example:

```
policy-scan-reports
```

Reports are written under the `reports/` prefix. No folders need to be created manually.

---

### 2. Create a Lambda execution role

- Trusted entity: **AWS service → Lambda**
- Attach the managed policy:
  - `AWSLambdaBasicExecutionRole`
- Add an inline policy allowing:
  - Read-only IAM access
  - `s3:PutObject` to `policy-scan-reports/reports/*`

---

### 3. Deploy the Lambda function

- Runtime: **Python 3.12**
- Handler: `policy_scan.lambda_handler`
- Timeout: **60 seconds**
- Memory: **256 MB**

Optional environment variables:

```
REPORT_BUCKET=policy-scan-reports
REPORT_PREFIX=reports/
MAX_ITEMS=50
```

---

### 4. Create an EventBridge schedule

- Trigger type: **Schedule**
- Input payload:

```json
{}
```

---

## Screenshots

The screenshots contains:
- Successful Lambda execution
- Generated S3 audit report
- EventBridge schedule configuration

---

## Security considerations

- The Lambda role uses read-only IAM permissions
- No IAM resources are modified
- Reports are written to a restricted S3 prefix
- No credentials or account-specific data are hardcoded

---


## License

This project is licensed under the MIT License.
