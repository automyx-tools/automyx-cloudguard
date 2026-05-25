# Disclaimer

AutoMyx CloudGuard is a read-only AWS security and cost triage tool. It is provided for education, operational visibility, and first-pass investigation.

CloudGuard is not a replacement for:

- Professional security assessment
- Compliance audit
- Penetration test
- AWS Well-Architected Review
- SOC 2, ISO 27001, PCI DSS, HIPAA, or regulatory certification process
- AWS-native services such as Security Hub, GuardDuty, Config, Inspector, CloudTrail, IAM Access Analyzer, or Trusted Advisor

## No Warranty

The software is provided as-is. Findings may be incomplete, inaccurate, stale, or affected by AWS permissions, region selection, service availability, or API limits.

## Validate Before Action

Remediation commands and recommendations are shown for manual review. Do not run remediation commands in production until you understand the impact and have change approval.

## Read-Only Intent

CloudGuard is designed to use read-only AWS APIs. If you modify the code, IAM policy, or execution environment, you are responsible for validating that it remains read-only.

## Data Responsibility

Generated reports may contain sensitive cloud metadata, including account IDs, ARNs, resource names, DNS names, IP addresses, and misconfiguration details. Treat reports as confidential.

Do not publish real reports, screenshots, or PDF exports without redacting sensitive information.

## Cost Estimates

Cost findings are estimates and review signals. Actual AWS cost depends on region, pricing changes, usage, data processing, discounts, commitments, and account-specific billing terms.

## Public Repository Samples

Only demo or redacted sample reports should be committed to the public repository.
