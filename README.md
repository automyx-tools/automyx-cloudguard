# AutoMyx CloudGuard

Local read-only AWS security and cost triage with an offline executive dashboard.

AutoMyx CloudGuard helps engineers collect evidence quickly during AWS reviews. The CLI scanner runs locally, writes a JSON report, and the browser dashboard visualizes findings, scanned resources, and an executive summary. The dashboard can also be exported as PDF from the browser.

## Why CloudGuard

- Read-only by design
- Runs locally with your AWS profile or temporary credentials
- No SaaS account required
- No browser-based AWS key entry
- No report data sent to AutoMyx
- Demo mode for safe testing and screenshots
- Executive dashboard with scanned resource inventory
- PDF export for sharing a sanitized dashboard

## Workflow

```text
AWS account -> local Go CLI scanner -> automyx-report.json -> local browser dashboard -> optional PDF export
```

The browser UI is a report viewer only. It does not call AWS APIs and does not accept AWS access keys.

## Quick Start

Build the scanner:

```bash
go build -o automyx-cloudguard
```

Run a live scan:

```bash
export AWS_PROFILE=my-readonly-profile
./automyx-cloudguard --region ap-south-1 --output automyx-report.json
```

```powershell
$env:AWS_PROFILE="my-readonly-profile"
.\automyx-cloudguard.exe --region ap-south-1 --output automyx-report.json

Open the dashboard:

```text
index.html
```

Upload:

```text
automyx-report.json
```

## Demo Mode

Demo mode does not call AWS APIs.

```bash
./automyx-cloudguard --demo --output samples/automyx-demo-report.json
```

Use the sample report in `samples/automyx-demo-report.json` for screenshots, testing, and demos.

## Region Behavior

Use `--region` to choose the target region:

```bash
./automyx-cloudguard --region us-east-1 --output automyx-report.json
```

If `--region` is not provided, CloudGuard uses the region from your AWS profile or `AWS_REGION`. If neither is set, it uses `us-east-1`.

CloudFront and Route 53 are global services. CloudGuard signs those global API calls with `us-east-1` and reports those resources as `global`.

ACM is scanned in the selected region and also in `us-east-1` when the selected region is different, so CloudFront certificates are covered.

## Dashboard PDF Export

After uploading a report:

1. Open the Executive Dashboard tab.
2. Click **Download PDF**.
3. Choose **Save as PDF** in your browser print dialog.

Do not publish PDFs generated from real AWS accounts unless account IDs, ARNs, DNS names, IP addresses, and sensitive findings are redacted.

## What It Checks

See [CHECKS.md](CHECKS.md) for the current checklist and known gaps.

High-level coverage includes:

- IAM root MFA, users, roles, access keys, AdministratorAccess attachment
- S3 public access, public policy status, encryption, versioning
- EC2, VPC, subnet, route table, NACL, security group, EBS, Elastic IP, NAT Gateway
- ELBv2 load balancers, listeners, target groups, target health
- Auto Scaling groups
- RDS exposure, encryption, backups
- CloudFront viewer policy, certificates, WAF association
- Route 53 hosted zones, query logging, wildcard records
- ACM expiry and unused certificate review
- First-pass cost review signals

## Read-Only IAM Policy

Use [IAM-READONLY-POLICY.json](IAM-READONLY-POLICY.json) as a starting point for a temporary read-only role/session.

The policy is intentionally read-only. Review and adapt it to your own account governance model before use.

## Public Safety

Do not commit real scan outputs.

Ignored by default:

- `automyx-report.json`
- generated reports
- PDF exports
- built binaries

Safe to commit:

- demo report in `samples/`
- redacted screenshots
- source code
- docs

## Screenshots

Use PNG for screenshots. See [docs/screenshots/README.md](docs/screenshots/README.md).

Recommended screenshots:

- CLI demo scan
- Uploading demo report
- Executive Dashboard
- Scanned Resources table
- Findings list
- PDF export using demo data

## Security And Disclaimer

Read these before using CloudGuard in production:

- [SECURITY.md](SECURITY.md)
- [DISCLAIMER.md](DISCLAIMER.md)

CloudGuard is a triage tool, not a compliance certification tool. Validate findings before taking action.

## Build For Linux From Windows

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o automyx-cloudguard-linux
```

## License

MIT License. See [LICENSE](LICENSE).

## AutoMyx

AutoMyx builds practical tools and videos for real IT problems, cloud operations, root cause analysis, and production troubleshooting.

Website: https://www.automyx.tech

Contact: contact@automyx.tech
