# What CloudGuard Checks

CloudGuard performs read-only AWS security and cost triage. It focuses on high-signal checks that are useful during operational reviews.

## Identity

- STS caller identity
- IAM root MFA status from the IAM credential report
- IAM users
- IAM access keys older than 90 days
- IAM users with attached `AdministratorAccess`
- IAM roles with attached `AdministratorAccess`

## Storage

- S3 Public Access Block configuration
- S3 bucket policy public-status evaluation
- S3 default encryption verification
- S3 bucket versioning

## Compute And Network

- EC2 instances with public IPv4 addresses
- VPC inventory
- Subnet inventory
- Route tables with Internet Gateway default routes
- Network ACLs allowing public management or database ports
- Security groups exposing management or database ports to `0.0.0.0/0` or `::/0`
- Unattached EBS volumes
- Unassociated Elastic IP addresses
- NAT Gateway running cost review

## Load Balancing And Scaling

- Internet-facing Application/Network Load Balancer review
- Load balancers with HTTP listeners
- Internet-facing load balancers without HTTPS/TLS listeners
- Target groups with no registered targets
- Target groups with unhealthy targets
- Auto Scaling groups with disabled or unhealthy capacity

## Database

- RDS public accessibility
- RDS storage encryption
- RDS automated backup retention

## Edge And DNS

- CloudFront distributions allowing HTTP viewer requests
- CloudFront distributions using default certificates
- CloudFront distributions without WAF association
- Route 53 public hosted zones without query logging
- Route 53 public wildcard DNS records

## Certificates

- ACM certificate expiry within 30 days
- ACM certificates not associated with an AWS resource
- ACM in the selected region plus `us-east-1` for CloudFront certificate coverage

## Cost Review Signals

- Unattached EBS volumes
- Unassociated Elastic IPs
- NAT Gateway running cost review
- Empty target groups
- Unused ACM certificates

# What CloudGuard Does Not Check Yet

CloudGuard does not currently perform complete coverage for:

- AWS Organizations and SCPs
- CloudTrail configuration
- AWS Config rules
- GuardDuty findings
- Security Hub findings
- IAM Access Analyzer findings
- KMS key policies
- Secrets Manager secret rotation
- ECR image scanning
- Lambda function policies and public URLs
- ECS/EKS workload posture
- WAF rule quality
- CloudWatch alarm coverage
- Backup Vault coverage
- Multi-region scanning in one command
- Multi-account organization-wide aggregation
- Compliance mapping to SOC 2, PCI DSS, HIPAA, ISO 27001, or CIS

These are good candidates for future versions.

# Important Notes

- Findings are triage signals, not final audit conclusions.
- Some checks depend on IAM permissions. Missing permissions can reduce coverage.
- Region-scoped services are scanned in the selected region.
- CloudFront and Route 53 are treated as global services.
- ACM is scanned in the selected region and `us-east-1` when needed for CloudFront coverage.
