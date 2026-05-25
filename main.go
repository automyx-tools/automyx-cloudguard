package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type ScanMetadata struct {
	Tool      string `json:"tool"`
	Version   string `json:"version"`
	ScanTime  string `json:"scan_time"`
	AccountID string `json:"aws_account_id"`
	Region    string `json:"aws_region"`
	Status    string `json:"status"`
	Mode      string `json:"mode"`
}

type Summary struct {
	TotalChecked             int     `json:"total_checked"`
	TotalFindings            int     `json:"total_findings"`
	Critical                 int     `json:"critical"`
	High                     int     `json:"high"`
	Medium                   int     `json:"medium"`
	Low                      int     `json:"low"`
	CostSavingsMonthly       float64 `json:"cost_savings_monthly"`
	ServicesScanned          int     `json:"services_scanned"`
	ServicesDeployedInRegion int     `json:"services_deployed_in_region"`
}

type Finding struct {
	ID             string `json:"id"`
	Service        string `json:"service"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	ResourceID     string `json:"resource_id"`
	Evidence       string `json:"evidence"`
	RemediationCmd string `json:"remediation_cmd"`
	Impact         string `json:"impact"`
}

type ScannedResource struct {
	Service      string   `json:"service"`
	ResourceType string   `json:"resource_type"`
	ResourceID   string   `json:"resource_id"`
	Name         string   `json:"name"`
	Region       string   `json:"region"`
	Status       string   `json:"status"`
	Checks       []string `json:"checks"`
	FindingCount int      `json:"finding_count"`
}

type Report struct {
	Metadata  ScanMetadata      `json:"scan_metadata"`
	Summary   Summary           `json:"summary"`
	Findings  []Finding         `json:"findings"`
	Resources []ScannedResource `json:"scanned_resources"`
}

func main() {
	demo := flag.Bool("demo", false, "write a simulated demo report instead of scanning AWS")
	output := flag.String("output", "automyx-report.json", "path to output JSON report")
	regionFlag := flag.String("region", "", "AWS region to scan, for example ap-south-1 or us-east-1")
	flag.Parse()

	fmt.Println("==================================================")
	fmt.Println("     AutoMyx CloudGuard CLI - AWS Scanner")
	fmt.Println("     Evidence First. Action Second.")
	fmt.Println("==================================================")

	ctx := context.Background()
	var report Report

	if *demo {
		fmt.Println("[i] Demo mode selected. Report will contain simulated findings.")
		report = runSimulationScan()
	} else {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			fmt.Printf("[-] Unable to load AWS config: %v\n", err)
			fmt.Println("[i] Configure AWS credentials or run with --demo for sample data.")
			os.Exit(1)
		}

		if cfg.Region == "" {
			cfg.Region = "us-east-1"
		}
		if strings.TrimSpace(*regionFlag) != "" {
			cfg.Region = strings.TrimSpace(*regionFlag)
		}

		stsClient := sts.NewFromConfig(cfg)
		if _, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
			fmt.Printf("[-] Unable to verify AWS caller identity: %v\n", err)
			fmt.Println("[i] Configure AWS credentials or run with --demo for sample data.")
			os.Exit(1)
		}

		fmt.Println("[+] Active AWS credentials verified. Starting live account scan.")
		report = runLiveScan(ctx, cfg)
	}

	content, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Printf("[-] Error marshalling report: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, content, 0644); err != nil {
		fmt.Printf("[-] Error saving report: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("==================================================")
	fmt.Println("[+] Scan completed")
	fmt.Printf("[+] Report saved: %s\n", *output)
	fmt.Printf("[+] Account: %s\n", report.Metadata.AccountID)
	fmt.Printf("[+] Region: %s\n", report.Metadata.Region)
	fmt.Printf("[+] Mode: %s\n", report.Metadata.Mode)
	fmt.Printf("[+] Total checked: %d\n", report.Summary.TotalChecked)
	fmt.Printf("[+] Findings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("[+] Estimated monthly savings: $%.2f\n", report.Summary.CostSavingsMonthly)
	fmt.Println("==================================================")
}

func str(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func i32(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}

func b(v *bool) bool {
	return v != nil && *v
}

func resource(service, resourceType, id, name, region, status string, checks ...string) ScannedResource {
	return ScannedResource{
		Service:      service,
		ResourceType: resourceType,
		ResourceID:   id,
		Name:         name,
		Region:       region,
		Status:       status,
		Checks:       checks,
	}
}

func attachFindingCounts(resources []ScannedResource, findings []Finding) []ScannedResource {
	for idx := range resources {
		for _, finding := range findings {
			if finding.ResourceID == resources[idx].ResourceID {
				resources[idx].FindingCount++
			}
		}
	}
	return resources
}

func servicesScannedCount() int {
	return len([]string{
		"IAM",
		"S3",
		"EC2 / VPC",
		"EC2",
		"ELBv2",
		"Auto Scaling",
		"RDS",
		"CloudFront",
		"Route 53",
		"ACM",
	})
}

func servicesDeployedInRegion(resources []ScannedResource, region string) int {
	services := map[string]bool{}
	for _, item := range resources {
		if item.Region == region {
			services[item.Service] = true
		}
	}
	return len(services)
}

func runLiveScan(ctx context.Context, cfg aws.Config) Report {
	findings := []Finding{}
	resources := []ScannedResource{}
	costSavings := 0.0

	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	accountID := "unknown"
	if err == nil && identity.Account != nil {
		accountID = *identity.Account
	}

	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	iamClient := iam.NewFromConfig(cfg)
	fmt.Println("[*] Auditing IAM credential report and access keys...")
	resources = append(resources, resource("IAM", "Root Account", fmt.Sprintf("arn:aws:iam::%s:root", accountID), "<root_account>", "global", "CHECKED", "root_mfa_credential_report"))
	rootFindings, rootChecked := auditRootMFA(ctx, iamClient, accountID)
	findings = append(findings, rootFindings...)
	if rootChecked == 0 {
		resources[len(resources)-1].Status = "UNKNOWN"
	}

	userFindings, iamResources := auditIAMUsers(ctx, iamClient)
	findings = append(findings, userFindings...)
	resources = append(resources, iamResources...)

	roleFindings, roleResources := auditIAMRoles(ctx, iamClient)
	findings = append(findings, roleFindings...)
	resources = append(resources, roleResources...)

	s3Client := s3.NewFromConfig(cfg)
	fmt.Println("[*] Auditing S3 public access, encryption, and versioning controls...")
	s3Findings, s3Resources := auditS3Buckets(ctx, s3Client)
	findings = append(findings, s3Findings...)
	resources = append(resources, s3Resources...)

	ec2Client := ec2.NewFromConfig(cfg)
	fmt.Printf("[*] Auditing EC2 instances, VPCs, security groups, EBS volumes, and Elastic IPs in %s...\n", region)
	instanceFindings, instanceResources := auditEC2Instances(ctx, ec2Client, region)
	findings = append(findings, instanceFindings...)
	resources = append(resources, instanceResources...)

	vpcResources := auditVPCs(ctx, ec2Client, region)
	resources = append(resources, vpcResources...)

	subnetResources := auditSubnets(ctx, ec2Client, region)
	resources = append(resources, subnetResources...)

	routeFindings, routeResources := auditRouteTables(ctx, ec2Client, region)
	findings = append(findings, routeFindings...)
	resources = append(resources, routeResources...)

	naclFindings, naclResources := auditNetworkACLs(ctx, ec2Client, region)
	findings = append(findings, naclFindings...)
	resources = append(resources, naclResources...)

	sgFindings, sgResources := auditSecurityGroups(ctx, ec2Client, region)
	findings = append(findings, sgFindings...)
	resources = append(resources, sgResources...)

	volFindings, volResources, volSavings := auditEBSVolumes(ctx, ec2Client, region)
	findings = append(findings, volFindings...)
	resources = append(resources, volResources...)
	costSavings += volSavings

	eipFindings, eipResources, eipSavings := auditElasticIPs(ctx, ec2Client, region)
	findings = append(findings, eipFindings...)
	resources = append(resources, eipResources...)
	costSavings += eipSavings

	natFindings, natResources, natSavings := auditNATGateways(ctx, ec2Client, region)
	findings = append(findings, natFindings...)
	resources = append(resources, natResources...)
	costSavings += natSavings

	elbv2Client := elasticloadbalancingv2.NewFromConfig(cfg)
	fmt.Printf("[*] Auditing load balancers and target groups in %s...\n", region)
	lbFindings, lbResources := auditLoadBalancers(ctx, elbv2Client, region)
	findings = append(findings, lbFindings...)
	resources = append(resources, lbResources...)

	tgFindings, tgResources := auditTargetGroups(ctx, elbv2Client, region)
	findings = append(findings, tgFindings...)
	resources = append(resources, tgResources...)

	asgClient := autoscaling.NewFromConfig(cfg)
	fmt.Printf("[*] Auditing Auto Scaling groups in %s...\n", region)
	asgFindings, asgResources := auditAutoScalingGroups(ctx, asgClient, region)
	findings = append(findings, asgFindings...)
	resources = append(resources, asgResources...)

	rdsClient := rds.NewFromConfig(cfg)
	fmt.Printf("[*] Auditing RDS database instances in %s...\n", region)
	rdsFindings, rdsResources := auditRDSInstances(ctx, rdsClient, region)
	findings = append(findings, rdsFindings...)
	resources = append(resources, rdsResources...)

	cloudFrontConfig := cfg.Copy()
	cloudFrontConfig.Region = "us-east-1"
	cloudFrontClient := cloudfront.NewFromConfig(cloudFrontConfig)
	fmt.Println("[*] Auditing CloudFront distributions...")
	cfFindings, cfResources := auditCloudFrontDistributions(ctx, cloudFrontClient)
	findings = append(findings, cfFindings...)
	resources = append(resources, cfResources...)

	route53Client := route53.NewFromConfig(cfg)
	fmt.Println("[*] Auditing Route 53 hosted zones and records...")
	r53Findings, r53Resources := auditRoute53(ctx, route53Client)
	findings = append(findings, r53Findings...)
	resources = append(resources, r53Resources...)

	acmClient := acm.NewFromConfig(cfg)
	fmt.Printf("[*] Auditing ACM certificates in %s...\n", region)
	acmFindings, acmResources := auditACMCertificates(ctx, acmClient, region)
	findings = append(findings, acmFindings...)
	resources = append(resources, acmResources...)
	if region != "us-east-1" {
		acmUSEastConfig := cfg.Copy()
		acmUSEastConfig.Region = "us-east-1"
		acmUSEastClient := acm.NewFromConfig(acmUSEastConfig)
		fmt.Println("[*] Auditing ACM certificates in us-east-1 for CloudFront usage...")
		usEastFindings, usEastResources := auditACMCertificates(ctx, acmUSEastClient, "us-east-1")
		findings = append(findings, usEastFindings...)
		resources = append(resources, usEastResources...)
	}

	critical, high, medium, low := severityCounts(findings)
	resources = attachFindingCounts(resources, findings)

	return Report{
		Metadata: ScanMetadata{
			Tool:      "AutoMyx CloudGuard CLI",
			Version:   "1.1.0",
			ScanTime:  time.Now().UTC().Format(time.RFC3339),
			AccountID: accountID,
			Region:    region,
			Status:    "COMPLETED",
			Mode:      "LIVE",
		},
		Summary: Summary{
			TotalChecked:             len(resources),
			TotalFindings:            len(findings),
			Critical:                 critical,
			High:                     high,
			Medium:                   medium,
			Low:                      low,
			CostSavingsMonthly:       costSavings,
			ServicesScanned:          servicesScannedCount(),
			ServicesDeployedInRegion: servicesDeployedInRegion(resources, region),
		},
		Findings:  findings,
		Resources: resources,
	}
}

func auditRootMFA(ctx context.Context, client *iam.Client, accountID string) ([]Finding, int) {
	checked := 1
	_, _ = client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})

	var content []byte
	for attempt := 0; attempt < 8; attempt++ {
		report, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil && len(report.Content) > 0 {
			content = report.Content
			break
		}
		time.Sleep(2 * time.Second)
	}

	if len(content) == 0 {
		return []Finding{{
			ID:             "SEC-IAM-CREDENTIAL-REPORT-UNAVAILABLE",
			Service:        "IAM",
			Category:       "SECURITY",
			Severity:       "LOW",
			Title:          "IAM Credential Report Could Not Be Read",
			Description:    "CloudGuard could not retrieve the IAM credential report, so root MFA state could not be verified.",
			ResourceID:     fmt.Sprintf("arn:aws:iam::%s:root", accountID),
			Evidence:       "iam:GenerateCredentialReport or iam:GetCredentialReport failed or did not return content.",
			RemediationCmd: "aws iam get-credential-report",
			Impact:         "Root MFA status is unknown until the credential report can be read.",
		}}, checked
	}

	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return []Finding{{
			ID:             "SEC-IAM-CREDENTIAL-REPORT-PARSE",
			Service:        "IAM",
			Category:       "SECURITY",
			Severity:       "LOW",
			Title:          "IAM Credential Report Could Not Be Parsed",
			Description:    "CloudGuard retrieved the IAM credential report but could not parse it.",
			ResourceID:     fmt.Sprintf("arn:aws:iam::%s:root", accountID),
			Evidence:       "Credential report CSV parsing failed.",
			RemediationCmd: "aws iam get-credential-report",
			Impact:         "Root MFA status is unknown until the credential report can be parsed.",
		}}, checked
	}

	header := map[string]int{}
	for idx, name := range records[0] {
		header[name] = idx
	}

	userIdx, hasUser := header["user"]
	mfaIdx, hasMFA := header["mfa_active"]
	if !hasUser || !hasMFA {
		return nil, checked
	}

	for _, row := range records[1:] {
		if len(row) <= userIdx || row[userIdx] != "<root_account>" {
			continue
		}
		mfaActive := ""
		if len(row) > mfaIdx {
			mfaActive = strings.ToLower(strings.TrimSpace(row[mfaIdx]))
		}
		if mfaActive != "true" {
			return []Finding{{
				ID:             "SEC-IAM-ROOT-MFA",
				Service:        "IAM",
				Category:       "SECURITY",
				Severity:       "CRITICAL",
				Title:          "Root Account Multi-Factor Authentication (MFA) Missing",
				Description:    "The AWS root account does not have MFA enabled according to the IAM credential report.",
				ResourceID:     fmt.Sprintf("arn:aws:iam::%s:root", accountID),
				Evidence:       fmt.Sprintf("Credential report row user=<root_account> mfa_active=%s", mfaActive),
				RemediationCmd: "Enable MFA for the root user in the AWS Console under Security credentials.",
				Impact:         "Root credentials without MFA create a high-impact account takeover risk.",
			}}, checked
		}
		return nil, checked
	}

	return nil, checked
}

func auditIAMUsers(ctx context.Context, client *iam.Client) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, user := range page.Users {
			userName := str(user.UserName)
			userArn := str(user.Arn)
			resources = append(resources, resource("IAM", "User", userArn, userName, "global", "CHECKED", "access_key_age", "administrator_managed_policy"))

			attachedPolicies := iam.NewListAttachedUserPoliciesPaginator(client, &iam.ListAttachedUserPoliciesInput{UserName: user.UserName})
			for attachedPolicies.HasMorePages() {
				policyPage, err := attachedPolicies.NextPage(ctx)
				if err != nil {
					break
				}
				for _, policy := range policyPage.AttachedPolicies {
					if isAdministratorPolicy(str(policy.PolicyArn), str(policy.PolicyName)) {
						findings = append(findings, Finding{
							ID:             fmt.Sprintf("SEC-IAM-USER-ADMIN-%s", userName),
							Service:        "IAM",
							Category:       "SECURITY",
							Severity:       "HIGH",
							Title:          "IAM User Has AdministratorAccess",
							Description:    fmt.Sprintf("IAM user '%s' has the AWS managed AdministratorAccess policy attached.", userName),
							ResourceID:     userArn,
							Evidence:       fmt.Sprintf("AttachedPolicy=%s PolicyArn=%s", str(policy.PolicyName), str(policy.PolicyArn)),
							RemediationCmd: fmt.Sprintf("aws iam detach-user-policy --user-name %s --policy-arn %s", userName, str(policy.PolicyArn)),
							Impact:         "Long-lived IAM users with full administrative permissions increase the impact of credential theft.",
						})
					}
				}
			}

			keyPaginator := iam.NewListAccessKeysPaginator(client, &iam.ListAccessKeysInput{UserName: user.UserName})
			for keyPaginator.HasMorePages() {
				keyPage, err := keyPaginator.NextPage(ctx)
				if err != nil {
					break
				}
				for _, key := range keyPage.AccessKeyMetadata {
					keyID := str(key.AccessKeyId)
					resources = append(resources, resource("IAM", "Access Key", keyID, userName, "global", string(key.Status), "key_age", "key_status"))
					if key.CreateDate == nil {
						continue
					}
					ageDays := time.Since(*key.CreateDate).Hours() / 24
					if ageDays <= 90 {
						continue
					}
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("SEC-IAM-KEY-%s", str(key.AccessKeyId)),
						Service:        "IAM",
						Category:       "SECURITY",
						Severity:       "HIGH",
						Title:          "Stale AWS Access Key Active",
						Description:    fmt.Sprintf("Access key %s for IAM user '%s' is %.0f days old.", str(key.AccessKeyId), str(user.UserName), ageDays),
						ResourceID:     str(user.Arn),
						Evidence:       fmt.Sprintf("AccessKeyId=%s AgeDays=%.0f Status=%s", str(key.AccessKeyId), ageDays, key.Status),
						RemediationCmd: fmt.Sprintf("aws iam update-access-key --user-name %s --access-key-id %s --status Inactive", str(user.UserName), str(key.AccessKeyId)),
						Impact:         "Long-lived active access keys increase blast radius if credentials are leaked.",
					})
				}
			}
		}
	}

	return findings, resources
}

func auditIAMRoles(ctx context.Context, client *iam.Client) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, role := range page.Roles {
			roleName := str(role.RoleName)
			roleArn := str(role.Arn)
			resources = append(resources, resource("IAM", "Role", roleArn, roleName, "global", "CHECKED", "administrator_managed_policy", "trust_policy_age"))

			attachedPolicies := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{RoleName: role.RoleName})
			for attachedPolicies.HasMorePages() {
				policyPage, err := attachedPolicies.NextPage(ctx)
				if err != nil {
					break
				}
				for _, policy := range policyPage.AttachedPolicies {
					if isAdministratorPolicy(str(policy.PolicyArn), str(policy.PolicyName)) {
						findings = append(findings, Finding{
							ID:             fmt.Sprintf("SEC-IAM-ROLE-ADMIN-%s", roleName),
							Service:        "IAM",
							Category:       "SECURITY",
							Severity:       "MEDIUM",
							Title:          "IAM Role Has AdministratorAccess",
							Description:    fmt.Sprintf("IAM role '%s' has the AWS managed AdministratorAccess policy attached.", roleName),
							ResourceID:     roleArn,
							Evidence:       fmt.Sprintf("AttachedPolicy=%s PolicyArn=%s", str(policy.PolicyName), str(policy.PolicyArn)),
							RemediationCmd: fmt.Sprintf("aws iam detach-role-policy --role-name %s --policy-arn %s", roleName, str(policy.PolicyArn)),
							Impact:         "Administrator roles may be valid for break-glass or platform automation, but they should be tightly controlled and assumed only through trusted paths.",
						})
					}
				}
			}
		}
	}

	return findings, resources
}

func isAdministratorPolicy(policyArn, policyName string) bool {
	return policyName == "AdministratorAccess" || strings.HasSuffix(policyArn, ":policy/AdministratorAccess")
}

func auditS3Buckets(ctx context.Context, client *s3.Client) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource

	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return findings, resources
	}

	for _, bucket := range out.Buckets {
		name := str(bucket.Name)
		bucketArn := fmt.Sprintf("arn:aws:s3:::%s", name)
		status := "CHECKED"
		pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: bucket.Name})
		publicBlockWeak := err != nil || pab.PublicAccessBlockConfiguration == nil
		if !publicBlockWeak {
			conf := pab.PublicAccessBlockConfiguration
			publicBlockWeak = conf.BlockPublicAcls == nil || !*conf.BlockPublicAcls ||
				conf.IgnorePublicAcls == nil || !*conf.IgnorePublicAcls ||
				conf.BlockPublicPolicy == nil || !*conf.BlockPublicPolicy ||
				conf.RestrictPublicBuckets == nil || !*conf.RestrictPublicBuckets
		}
		if publicBlockWeak {
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("SEC-S3-PAB-%s", name),
				Service:        "S3",
				Category:       "SECURITY",
				Severity:       "MEDIUM",
				Title:          "S3 Public Access Block Not Fully Enabled",
				Description:    fmt.Sprintf("Bucket '%s' does not have all S3 Public Access Block controls enabled. This is a preventive-control finding, not proof that the bucket is publicly readable.", name),
				ResourceID:     bucketArn,
				Evidence:       "At least one of BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, or RestrictPublicBuckets is false or unavailable.",
				RemediationCmd: fmt.Sprintf("aws s3api put-public-access-block --bucket %s --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", name),
				Impact:         "Weak public access block settings increase the chance of accidental public exposure if a permissive ACL or policy is added.",
			})
		}

		policyStatus, policyStatusErr := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: bucket.Name})
		if policyStatusErr == nil && policyStatus.PolicyStatus != nil && b(policyStatus.PolicyStatus.IsPublic) {
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("SEC-S3-PUBLIC-POLICY-%s", name),
				Service:        "S3",
				Category:       "SECURITY",
				Severity:       "HIGH",
				Title:          "S3 Bucket Policy Evaluates As Public",
				Description:    fmt.Sprintf("AWS reports bucket '%s' policy status as public.", name),
				ResourceID:     bucketArn,
				Evidence:       "GetBucketPolicyStatus returned IsPublic=true.",
				RemediationCmd: fmt.Sprintf("aws s3api put-public-access-block --bucket %s --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", name),
				Impact:         "A public bucket policy can expose data to unauthenticated users depending on object policy and ACL combinations.",
			})
		}

		_, encryptionErr := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket.Name})
		if encryptionErr != nil {
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("SEC-S3-ENCRYPTION-%s", name),
				Service:        "S3",
				Category:       "SECURITY",
				Severity:       "LOW",
				Title:          "S3 Default Encryption Could Not Be Verified",
				Description:    fmt.Sprintf("CloudGuard could not verify default encryption for bucket '%s'. Confirm that server-side encryption is enabled.", name),
				ResourceID:     bucketArn,
				Evidence:       "GetBucketEncryption did not return a usable encryption configuration.",
				RemediationCmd: fmt.Sprintf("aws s3api put-bucket-encryption --bucket %s --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'", name),
				Impact:         "Missing default encryption can allow new objects to be stored without expected encryption controls.",
			})
		}

		versioning, versioningErr := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket.Name})
		if versioningErr != nil {
			status = "PARTIAL"
		} else if string(versioning.Status) != "Enabled" {
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("SEC-S3-VERSIONING-%s", name),
				Service:        "S3",
				Category:       "SECURITY",
				Severity:       "LOW",
				Title:          "S3 Bucket Versioning Not Enabled",
				Description:    fmt.Sprintf("Bucket '%s' does not have versioning enabled.", name),
				ResourceID:     bucketArn,
				Evidence:       fmt.Sprintf("VersioningStatus=%s", versioning.Status),
				RemediationCmd: fmt.Sprintf("aws s3api put-bucket-versioning --bucket %s --versioning-configuration Status=Enabled", name),
				Impact:         "Versioning improves recovery from accidental deletion, overwrite, and some destructive events.",
			})
		}

		resources = append(resources, resource("S3", "Bucket", bucketArn, name, "global", status, "public_access_block", "bucket_policy_status", "default_encryption", "versioning"))
	}

	return findings, resources
}

func auditEC2Instances(ctx context.Context, client *ec2.Client, region string) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				instanceID := str(instance.InstanceId)
				name := instanceID
				for _, tag := range instance.Tags {
					if str(tag.Key) == "Name" && str(tag.Value) != "" {
						name = str(tag.Value)
						break
					}
				}
				status := string(instance.State.Name)
				checks := []string{"state", "public_ip", "source_dest_check"}
				if instance.PublicIpAddress != nil {
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("SEC-EC2-PUBLIC-IP-%s", instanceID),
						Service:        "EC2 / Instances",
						Category:       "SECURITY",
						Severity:       "MEDIUM",
						Title:          "EC2 Instance Has Public IPv4 Address",
						Description:    fmt.Sprintf("EC2 instance '%s' has a public IPv4 address assigned.", instanceID),
						ResourceID:     instanceID,
						Evidence:       fmt.Sprintf("PublicIpAddress=%s State=%s", str(instance.PublicIpAddress), status),
						RemediationCmd: "Review whether this workload requires a public IP. Prefer private subnets behind ALB, VPN, or SSM Session Manager.",
						Impact:         "Public instance addressing increases exposure and should be intentional, restricted, and monitored.",
					})
				}
				resources = append(resources, resource("EC2", "Instance", instanceID, name, region, status, checks...))
			}
		}
	}

	return findings, resources
}

func auditVPCs(ctx context.Context, client *ec2.Client, region string) []ScannedResource {
	var resources []ScannedResource
	paginator := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return resources
		}
		for _, vpc := range page.Vpcs {
			name := str(vpc.VpcId)
			for _, tag := range vpc.Tags {
				if str(tag.Key) == "Name" && str(tag.Value) != "" {
					name = str(tag.Value)
					break
				}
			}
			status := "available"
			if vpc.State != "" {
				status = string(vpc.State)
			}
			resources = append(resources, resource("EC2 / VPC", "VPC", str(vpc.VpcId), name, region, status, "cidr_block", "default_vpc_flag"))
		}
	}

	return resources
}

func auditSubnets(ctx context.Context, client *ec2.Client, region string) []ScannedResource {
	var resources []ScannedResource
	paginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return resources
		}
		for _, subnet := range page.Subnets {
			name := str(subnet.SubnetId)
			for _, tag := range subnet.Tags {
				if str(tag.Key) == "Name" && str(tag.Value) != "" {
					name = str(tag.Value)
					break
				}
			}
			resources = append(resources, resource("EC2 / VPC", "Subnet", str(subnet.SubnetId), name, region, string(subnet.State), "map_public_ip_on_launch", "available_ip_count", "vpc_association"))
		}
	}

	return resources
}

func auditRouteTables(ctx context.Context, client *ec2.Client, region string) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, rt := range page.RouteTables {
			routeTableID := str(rt.RouteTableId)
			name := routeTableID
			for _, tag := range rt.Tags {
				if str(tag.Key) == "Name" && str(tag.Value) != "" {
					name = str(tag.Value)
					break
				}
			}
			resources = append(resources, resource("EC2 / VPC", "Route Table", routeTableID, name, region, "CHECKED", "internet_gateway_default_route", "subnet_associations"))
			for _, route := range rt.Routes {
				if str(route.DestinationCidrBlock) == "0.0.0.0/0" && strings.HasPrefix(str(route.GatewayId), "igw-") {
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("SEC-VPC-ROUTE-IGW-%s", routeTableID),
						Service:        "EC2 / VPC",
						Category:       "SECURITY",
						Severity:       "LOW",
						Title:          "Route Table Has Internet Gateway Default Route",
						Description:    fmt.Sprintf("Route table '%s' sends IPv4 default traffic to an Internet Gateway.", routeTableID),
						ResourceID:     routeTableID,
						Evidence:       fmt.Sprintf("Destination=0.0.0.0/0 GatewayId=%s State=%s", str(route.GatewayId), route.State),
						RemediationCmd: "Confirm associated subnets are intentionally public. Private subnets should route through NAT Gateway, firewall, or no internet route.",
						Impact:         "Internet-routed subnets can expose workloads when combined with public IPs and permissive security controls.",
					})
				}
			}
		}
	}

	return findings, resources
}

func auditNetworkACLs(ctx context.Context, client *ec2.Client, region string) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := ec2.NewDescribeNetworkAclsPaginator(client, &ec2.DescribeNetworkAclsInput{})
	dangerousPorts := map[int32]string{22: "SSH", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL", 1433: "SQL Server"}

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, nacl := range page.NetworkAcls {
			naclID := str(nacl.NetworkAclId)
			name := naclID
			for _, tag := range nacl.Tags {
				if str(tag.Key) == "Name" && str(tag.Value) != "" {
					name = str(tag.Value)
					break
				}
			}
			resources = append(resources, resource("EC2 / VPC", "Network ACL", naclID, name, region, "CHECKED", "public_inbound_management_ports", "public_inbound_database_ports"))
			for _, entry := range nacl.Entries {
				if entry.Egress != nil && *entry.Egress {
					continue
				}
				if strings.ToLower(string(entry.RuleAction)) != "allow" {
					continue
				}
				cidr := str(entry.CidrBlock)
				if cidr == "" {
					cidr = str(entry.Ipv6CidrBlock)
				}
				if cidr != "0.0.0.0/0" && cidr != "::/0" {
					continue
				}
				for port, label := range dangerousPorts {
					if !naclIncludesPort(entry.Protocol, entry.PortRange, port) {
						continue
					}
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("SEC-VPC-NACL-%s-%d", naclID, port),
						Service:        "EC2 / VPC",
						Category:       "SECURITY",
						Severity:       "MEDIUM",
						Title:          fmt.Sprintf("Network ACL Allows Public %s Traffic", label),
						Description:    fmt.Sprintf("Network ACL '%s' allows inbound %s traffic from %s.", naclID, label, cidr),
						ResourceID:     naclID,
						Evidence:       fmt.Sprintf("Rule=%d Action=%s Protocol=%s Port=%d Source=%s", i32(entry.RuleNumber), entry.RuleAction, str(entry.Protocol), port, cidr),
						RemediationCmd: "Review subnet-level NACL rules and restrict inbound sources for management and database ports.",
						Impact:         "Permissive NACLs do not expose traffic alone, but they remove an important subnet-level guardrail.",
					})
				}
			}
		}
	}

	return findings, resources
}

func auditSecurityGroups(ctx context.Context, client *ec2.Client, region string) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	dangerousPorts := map[int32]string{
		22:   "SSH",
		3389: "RDP",
		5432: "PostgreSQL",
		3306: "MySQL",
		1433: "SQL Server",
	}

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, sg := range page.SecurityGroups {
			resources = append(resources, resource("EC2 / Security Groups", "Security Group", str(sg.GroupId), str(sg.GroupName), region, "CHECKED", "public_ingress_management_ports", "public_ingress_database_ports"))
			for _, rule := range sg.IpPermissions {
				publicSources := publicCIDRS(rule.IpRanges, rule.Ipv6Ranges)
				if len(publicSources) == 0 {
					continue
				}

				for port, label := range dangerousPorts {
					if !ruleIncludesPort(rule.IpProtocol, rule.FromPort, rule.ToPort, port) {
						continue
					}
					for _, cidr := range publicSources {
						findings = append(findings, securityGroupFinding(str(sg.GroupId), str(sg.GroupName), port, label, cidr))
					}
				}
			}
		}
	}

	return findings, resources
}

func publicCIDRS(ipRanges []types.IpRange, ipv6Ranges []types.Ipv6Range) []string {
	var cidrs []string
	for _, ipRange := range ipRanges {
		if str(ipRange.CidrIp) == "0.0.0.0/0" {
			cidrs = append(cidrs, "0.0.0.0/0")
		}
	}
	for _, ipRange := range ipv6Ranges {
		if str(ipRange.CidrIpv6) == "::/0" {
			cidrs = append(cidrs, "::/0")
		}
	}
	return cidrs
}

func ruleIncludesPort(protocol *string, fromPort, toPort *int32, port int32) bool {
	if protocol != nil && *protocol == "-1" {
		return true
	}
	if fromPort == nil && toPort == nil {
		return false
	}
	from := i32(fromPort)
	to := i32(toPort)
	if to == 0 {
		to = from
	}
	return from <= port && port <= to
}

func naclIncludesPort(protocol *string, portRange *types.PortRange, port int32) bool {
	if protocol != nil && (*protocol == "-1" || *protocol == "6") && portRange == nil {
		return true
	}
	if protocol != nil && *protocol != "-1" && *protocol != "6" {
		return false
	}
	if portRange == nil {
		return false
	}
	from := i32(portRange.From)
	to := i32(portRange.To)
	if to == 0 {
		to = from
	}
	return from <= port && port <= to
}

func securityGroupFinding(groupID, groupName string, port int32, label, cidr string) Finding {
	remediationCmd := fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol tcp --port %d --cidr %s", groupID, port, cidr)
	if cidr == "::/0" {
		remediationCmd = fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --ip-permissions IpProtocol=tcp,FromPort=%d,ToPort=%d,Ipv6Ranges='[{CidrIpv6=::/0}]'", groupID, port, port)
	}

	return Finding{
		ID:             fmt.Sprintf("SEC-EC2-SG-%s-%d-%s", groupID, port, strings.ReplaceAll(cidr, "/", "_")),
		Service:        "EC2 / Security Groups",
		Category:       "SECURITY",
		Severity:       "CRITICAL",
		Title:          fmt.Sprintf("%s Port Exposed to Public Internet", label),
		Description:    fmt.Sprintf("Security group '%s' (%s) allows public ingress on TCP port %d from %s.", groupName, groupID, port, cidr),
		ResourceID:     groupID,
		Evidence:       fmt.Sprintf("Ingress TCP Port=%d Source=%s", port, cidr),
		RemediationCmd: remediationCmd,
		Impact:         "Public management or database ports are exposed to internet scanning, brute force attempts, and direct exploit attempts.",
	}
}

func auditEBSVolumes(ctx context.Context, client *ec2.Client, region string) ([]Finding, []ScannedResource, float64) {
	var findings []Finding
	var resources []ScannedResource
	savings := 0.0
	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources, savings
		}
		for _, vol := range page.Volumes {
			volumeID := str(vol.VolumeId)
			resources = append(resources, resource("EC2 / EBS", "Volume", volumeID, volumeID, region, string(vol.State), "attachment_state", "volume_size", "volume_type"))
			if string(vol.State) != "available" {
				continue
			}
			sizeGB := i32(vol.Size)
			monthly := float64(sizeGB) * 0.08
			savings += monthly
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("COST-EBS-IDLE-%s", volumeID),
				Service:        "EC2 / EBS",
				Category:       "COST",
				Severity:       "MEDIUM",
				Title:          "Orphaned EBS Volume Incurring Costs",
				Description:    fmt.Sprintf("EBS volume %s is unattached and still billable.", volumeID),
				ResourceID:     volumeID,
				Evidence:       fmt.Sprintf("State=available Size=%dGB Type=%s EstimatedMonthlyCost=$%.2f", sizeGB, vol.VolumeType, monthly),
				RemediationCmd: fmt.Sprintf("aws ec2 delete-volume --volume-id %s", volumeID),
				Impact:         "Unattached volumes create ongoing storage cost until deleted after backup/retention review.",
			})
		}
	}

	return findings, resources, savings
}

func auditElasticIPs(ctx context.Context, client *ec2.Client, region string) ([]Finding, []ScannedResource, float64) {
	var findings []Finding
	var resources []ScannedResource
	savings := 0.0

	out, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return findings, resources, savings
	}

	for _, addr := range out.Addresses {
		allocationID := str(addr.AllocationId)
		status := "associated"
		if addr.AssociationId == nil {
			status = "unassociated"
		}
		resources = append(resources, resource("EC2 / Elastic IP", "Elastic IP", allocationID, str(addr.PublicIp), region, status, "association_state", "public_ipv4_charge"))
		if addr.AssociationId != nil {
			continue
		}
		monthly := 3.60
		savings += monthly
		findings = append(findings, Finding{
			ID:             fmt.Sprintf("COST-EIP-IDLE-%s", allocationID),
			Service:        "EC2 / Elastic IP",
			Category:       "COST",
			Severity:       "LOW",
			Title:          "Unattached Elastic IP Address",
			Description:    "Elastic IP address is allocated but not associated with a running resource.",
			ResourceID:     allocationID,
			Evidence:       fmt.Sprintf("PublicIp=%s AllocationId=%s AssociationId=<nil> EstimatedMonthlyCost=$%.2f", str(addr.PublicIp), allocationID, monthly),
			RemediationCmd: fmt.Sprintf("aws ec2 release-address --allocation-id %s", allocationID),
			Impact:         "Unused public IPv4 addresses incur ongoing hourly charges.",
		})
	}

	return findings, resources, savings
}

func auditNATGateways(ctx context.Context, client *ec2.Client, region string) ([]Finding, []ScannedResource, float64) {
	var findings []Finding
	var resources []ScannedResource
	savings := 0.0
	paginator := ec2.NewDescribeNatGatewaysPaginator(client, &ec2.DescribeNatGatewaysInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources, savings
		}
		for _, nat := range page.NatGateways {
			natID := str(nat.NatGatewayId)
			status := string(nat.State)
			name := natID
			for _, tag := range nat.Tags {
				if str(tag.Key) == "Name" && str(tag.Value) != "" {
					name = str(tag.Value)
					break
				}
			}
			resources = append(resources, resource("EC2 / VPC", "NAT Gateway", natID, name, region, status, "state", "subnet", "hourly_cost_awareness"))
			if status == "available" {
				monthly := 32.40
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("COST-NAT-REVIEW-%s", natID),
					Service:        "EC2 / VPC",
					Category:       "COST",
					Severity:       "LOW",
					Title:          "NAT Gateway Running Cost Review",
					Description:    fmt.Sprintf("NAT Gateway '%s' is available and incurs hourly charges plus data processing charges.", natID),
					ResourceID:     natID,
					Evidence:       fmt.Sprintf("State=%s EstimatedBaseMonthlyCost=$%.2f excluding data processing", status, monthly),
					RemediationCmd: "Review CloudWatch bytes processed and route-table usage before deleting or consolidating NAT Gateways.",
					Impact:         "Unused or over-provisioned NAT Gateways create recurring cost even when traffic is low.",
				})
			}
		}
	}

	return findings, resources, savings
}

func auditLoadBalancers(ctx context.Context, client *elasticloadbalancingv2.Client, region string) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, lb := range page.LoadBalancers {
			arn := str(lb.LoadBalancerArn)
			name := str(lb.LoadBalancerName)
			status := ""
			if lb.State != nil {
				status = string(lb.State.Code)
			}
			resources = append(resources, resource("ELBv2", "Load Balancer", arn, name, region, status, "scheme", "listeners", "tls_termination", "target_groups"))

			if string(lb.Scheme) == "internet-facing" {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-ELB-INTERNET-%s", sanitizeID(arn)),
					Service:        "ELBv2",
					Category:       "SECURITY",
					Severity:       "LOW",
					Title:          "Internet-Facing Load Balancer Review",
					Description:    fmt.Sprintf("Load balancer '%s' is internet-facing.", name),
					ResourceID:     arn,
					Evidence:       fmt.Sprintf("Scheme=%s Type=%s", lb.Scheme, lb.Type),
					RemediationCmd: "Confirm this load balancer is intended to be public and protected by TLS, WAF, and restrictive security groups.",
					Impact:         "Public load balancers are normal for internet apps, but should be intentional and protected.",
				})
			}

			listeners, err := client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn})
			if err != nil {
				continue
			}
			hasHTTPS := false
			for _, listener := range listeners.Listeners {
				protocol := string(listener.Protocol)
				if protocol == "HTTPS" || protocol == "TLS" {
					hasHTTPS = true
				}
				if protocol == "HTTP" && i32(listener.Port) == 80 && string(lb.Scheme) == "internet-facing" {
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("SEC-ELB-HTTP-%s-%d", sanitizeID(arn), i32(listener.Port)),
						Service:        "ELBv2",
						Category:       "SECURITY",
						Severity:       "MEDIUM",
						Title:          "Internet-Facing Load Balancer Has HTTP Listener",
						Description:    fmt.Sprintf("Load balancer '%s' has an HTTP listener on port 80.", name),
						ResourceID:     arn,
						Evidence:       fmt.Sprintf("ListenerProtocol=%s Port=%d Scheme=%s", protocol, i32(listener.Port), lb.Scheme),
						RemediationCmd: "Redirect HTTP to HTTPS or remove the HTTP listener when it is not required.",
						Impact:         "Plain HTTP listeners can expose user traffic and enable downgrade paths if not redirecting to HTTPS.",
					})
				}
			}
			if string(lb.Scheme) == "internet-facing" && !hasHTTPS {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-ELB-NO-HTTPS-%s", sanitizeID(arn)),
					Service:        "ELBv2",
					Category:       "SECURITY",
					Severity:       "HIGH",
					Title:          "Internet-Facing Load Balancer Has No HTTPS Listener",
					Description:    fmt.Sprintf("Load balancer '%s' has no HTTPS/TLS listener.", name),
					ResourceID:     arn,
					Evidence:       "No HTTPS or TLS listener returned by DescribeListeners.",
					RemediationCmd: "Add an HTTPS listener with an ACM certificate and redirect HTTP to HTTPS.",
					Impact:         "Public applications without HTTPS expose traffic and fail modern security expectations.",
				})
			}
		}
	}

	return findings, resources
}

func auditTargetGroups(ctx context.Context, client *elasticloadbalancingv2.Client, region string) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(client, &elasticloadbalancingv2.DescribeTargetGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, tg := range page.TargetGroups {
			arn := str(tg.TargetGroupArn)
			name := str(tg.TargetGroupName)
			resources = append(resources, resource("ELBv2", "Target Group", arn, name, region, string(tg.Protocol), "registered_targets", "target_health", "health_check"))
			health, err := client.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{TargetGroupArn: tg.TargetGroupArn})
			if err != nil {
				continue
			}
			if len(health.TargetHealthDescriptions) == 0 {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("COST-TG-NO-TARGETS-%s", sanitizeID(arn)),
					Service:        "ELBv2",
					Category:       "COST",
					Severity:       "LOW",
					Title:          "Target Group Has No Registered Targets",
					Description:    fmt.Sprintf("Target group '%s' has no registered targets.", name),
					ResourceID:     arn,
					Evidence:       "DescribeTargetHealth returned zero targets.",
					RemediationCmd: "Review whether this target group is still needed before deleting it.",
					Impact:         "Unused target groups can indicate stale load balancer configuration and operational clutter.",
				})
				continue
			}
			unhealthy := 0
			for _, desc := range health.TargetHealthDescriptions {
				if desc.TargetHealth != nil && string(desc.TargetHealth.State) != "healthy" {
					unhealthy++
				}
			}
			if unhealthy > 0 {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-TG-UNHEALTHY-%s", sanitizeID(arn)),
					Service:        "ELBv2",
					Category:       "SECURITY",
					Severity:       "MEDIUM",
					Title:          "Target Group Has Unhealthy Targets",
					Description:    fmt.Sprintf("Target group '%s' has %d unhealthy/non-healthy targets.", name, unhealthy),
					ResourceID:     arn,
					Evidence:       fmt.Sprintf("UnhealthyTargets=%d TotalTargets=%d", unhealthy, len(health.TargetHealthDescriptions)),
					RemediationCmd: "Investigate target health checks, application ports, security groups, and instance/container health.",
					Impact:         "Unhealthy targets reduce availability and can cause partial outages.",
				})
			}
		}
	}

	return findings, resources
}

func auditAutoScalingGroups(ctx context.Context, client *autoscaling.Client, region string) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(client, &autoscaling.DescribeAutoScalingGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, group := range page.AutoScalingGroups {
			name := str(group.AutoScalingGroupName)
			arn := str(group.AutoScalingGroupARN)
			if arn == "" {
				arn = name
			}
			status := "CHECKED"
			resources = append(resources, resource("Auto Scaling", "Auto Scaling Group", arn, name, region, status, "desired_capacity", "min_max_capacity", "instance_health"))
			desired := i32(group.DesiredCapacity)
			minSize := i32(group.MinSize)
			maxSize := i32(group.MaxSize)
			if maxSize == 0 {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-ASG-MAX-ZERO-%s", sanitizeID(arn)),
					Service:        "Auto Scaling",
					Category:       "SECURITY",
					Severity:       "MEDIUM",
					Title:          "Auto Scaling Group Cannot Launch Instances",
					Description:    fmt.Sprintf("Auto Scaling group '%s' has MaxSize set to 0.", name),
					ResourceID:     arn,
					Evidence:       fmt.Sprintf("MinSize=%d DesiredCapacity=%d MaxSize=%d", minSize, desired, maxSize),
					RemediationCmd: "Review whether this group is intentionally disabled. Increase MaxSize if it should serve traffic.",
					Impact:         "An ASG with MaxSize 0 cannot recover capacity during failures.",
				})
			}
			if desired > 0 && len(group.Instances) == 0 {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-ASG-NO-INSTANCES-%s", sanitizeID(arn)),
					Service:        "Auto Scaling",
					Category:       "SECURITY",
					Severity:       "HIGH",
					Title:          "Auto Scaling Group Desired Capacity Has No Instances",
					Description:    fmt.Sprintf("Auto Scaling group '%s' has desired capacity %d but no instances.", name, desired),
					ResourceID:     arn,
					Evidence:       fmt.Sprintf("DesiredCapacity=%d Instances=0", desired),
					RemediationCmd: "Check launch template, subnet capacity, instance quotas, and scaling activity failures.",
					Impact:         "Expected application capacity is missing and may cause outage.",
				})
			}
			unhealthy := 0
			for _, instance := range group.Instances {
				if str(instance.HealthStatus) != "Healthy" {
					unhealthy++
				}
			}
			if unhealthy > 0 {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-ASG-UNHEALTHY-%s", sanitizeID(arn)),
					Service:        "Auto Scaling",
					Category:       "SECURITY",
					Severity:       "MEDIUM",
					Title:          "Auto Scaling Group Has Unhealthy Instances",
					Description:    fmt.Sprintf("Auto Scaling group '%s' has %d unhealthy instances.", name, unhealthy),
					ResourceID:     arn,
					Evidence:       fmt.Sprintf("UnhealthyInstances=%d TotalInstances=%d", unhealthy, len(group.Instances)),
					RemediationCmd: "Review ASG health checks, instance status, and recent scaling activity.",
					Impact:         "Unhealthy capacity can reduce availability and delay recovery.",
				})
			}
		}
	}

	return findings, resources
}

func auditRDSInstances(ctx context.Context, client *rds.Client, region string) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, db := range page.DBInstances {
			id := str(db.DBInstanceArn)
			name := str(db.DBInstanceIdentifier)
			if id == "" {
				id = name
			}
			status := str(db.DBInstanceStatus)
			resources = append(resources, resource("RDS", "DB Instance", id, name, region, status, "storage_encryption", "public_accessibility", "backup_retention"))

			if db.PubliclyAccessible != nil && *db.PubliclyAccessible {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-RDS-PUBLIC-%s", name),
					Service:        "RDS",
					Category:       "SECURITY",
					Severity:       "HIGH",
					Title:          "RDS Instance Publicly Accessible",
					Description:    fmt.Sprintf("RDS instance '%s' is marked as publicly accessible.", name),
					ResourceID:     id,
					Evidence:       "PubliclyAccessible=true",
					RemediationCmd: "Modify the DB instance to disable public accessibility and place it in private subnets.",
					Impact:         "Public database endpoints increase exposure to internet scanning, credential attacks, and direct exploit attempts.",
				})
			}

			if db.StorageEncrypted != nil && !*db.StorageEncrypted {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-RDS-ENCRYPTION-%s", name),
					Service:        "RDS",
					Category:       "SECURITY",
					Severity:       "MEDIUM",
					Title:          "RDS Storage Encryption Disabled",
					Description:    fmt.Sprintf("RDS instance '%s' does not have storage encryption enabled.", name),
					ResourceID:     id,
					Evidence:       "StorageEncrypted=false",
					RemediationCmd: "Create an encrypted snapshot copy and restore the database from the encrypted snapshot.",
					Impact:         "Unencrypted database storage weakens data protection and can violate compliance requirements.",
				})
			}

			if db.BackupRetentionPeriod == nil || *db.BackupRetentionPeriod == 0 {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-RDS-BACKUP-%s", name),
					Service:        "RDS",
					Category:       "SECURITY",
					Severity:       "MEDIUM",
					Title:          "RDS Automated Backups Disabled",
					Description:    fmt.Sprintf("RDS instance '%s' has no automated backup retention.", name),
					ResourceID:     id,
					Evidence:       fmt.Sprintf("BackupRetentionPeriod=%d", i32(db.BackupRetentionPeriod)),
					RemediationCmd: "Enable automated backups with a retention period aligned to recovery requirements.",
					Impact:         "Without automated backups, recovery from accidental deletion, corruption, or bad deployment is harder.",
				})
			}
		}
	}

	return findings, resources
}

func auditCloudFrontDistributions(ctx context.Context, client *cloudfront.Client) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		if page.DistributionList == nil {
			continue
		}
		for _, dist := range page.DistributionList.Items {
			id := str(dist.Id)
			name := str(dist.DomainName)
			status := str(dist.Status)
			if status == "" && b(dist.Enabled) {
				status = "Enabled"
			}
			resources = append(resources, resource("CloudFront", "Distribution", id, name, "global", status, "viewer_protocol_policy", "custom_certificate", "waf_association"))

			if dist.DefaultCacheBehavior != nil && string(dist.DefaultCacheBehavior.ViewerProtocolPolicy) == "allow-all" {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-CF-HTTP-ALLOWED-%s", id),
					Service:        "CloudFront",
					Category:       "SECURITY",
					Severity:       "MEDIUM",
					Title:          "CloudFront Allows HTTP Viewer Requests",
					Description:    fmt.Sprintf("CloudFront distribution '%s' allows viewers to use HTTP.", id),
					ResourceID:     id,
					Evidence:       "DefaultCacheBehavior.ViewerProtocolPolicy=allow-all",
					RemediationCmd: "Update the distribution viewer protocol policy to redirect-to-https or https-only.",
					Impact:         "Allowing HTTP can expose users to plaintext traffic and downgrade paths.",
				})
			}

			if dist.ViewerCertificate != nil && b(dist.ViewerCertificate.CloudFrontDefaultCertificate) {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-CF-DEFAULT-CERT-%s", id),
					Service:        "CloudFront",
					Category:       "SECURITY",
					Severity:       "LOW",
					Title:          "CloudFront Uses Default Certificate",
					Description:    fmt.Sprintf("CloudFront distribution '%s' uses the default CloudFront certificate.", id),
					ResourceID:     id,
					Evidence:       "ViewerCertificate.CloudFrontDefaultCertificate=true",
					RemediationCmd: "Attach an ACM certificate for the custom domain if this distribution serves a branded hostname.",
					Impact:         "Default certificates are fine for cloudfront.net testing, but production custom domains should use managed certificates.",
				})
			}

			if dist.WebACLId == nil || str(dist.WebACLId) == "" {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-CF-NO-WAF-%s", id),
					Service:        "CloudFront",
					Category:       "SECURITY",
					Severity:       "LOW",
					Title:          "CloudFront Distribution Has No WAF Association",
					Description:    fmt.Sprintf("CloudFront distribution '%s' has no Web ACL associated.", id),
					ResourceID:     id,
					Evidence:       "WebACLId is empty.",
					RemediationCmd: "Attach an AWS WAF Web ACL when the distribution fronts public applications or APIs.",
					Impact:         "WAF is not mandatory for every static site, but public applications benefit from managed rule protections and rate limiting.",
				})
			}
		}
	}

	return findings, resources
}

func auditRoute53(ctx context.Context, client *route53.Client) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, zone := range page.HostedZones {
			zoneID := cleanHostedZoneID(str(zone.Id))
			name := strings.TrimSuffix(str(zone.Name), ".")
			scope := "public"
			if zone.Config != nil && zone.Config.PrivateZone {
				scope = "private"
			}
			resources = append(resources, resource("Route 53", "Hosted Zone", zoneID, name, "global", scope, "record_sets", "query_logging", "wildcard_records"))

			if scope == "public" {
				queryLogging, err := client.ListQueryLoggingConfigs(ctx, &route53.ListQueryLoggingConfigsInput{HostedZoneId: aws.String(zoneID)})
				if err == nil && len(queryLogging.QueryLoggingConfigs) == 0 {
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("SEC-R53-NO-QUERY-LOGS-%s", sanitizeID(zoneID)),
						Service:        "Route 53",
						Category:       "SECURITY",
						Severity:       "LOW",
						Title:          "Route 53 Public Zone Has No Query Logging",
						Description:    fmt.Sprintf("Public hosted zone '%s' has no Route 53 query logging configuration.", name),
						ResourceID:     zoneID,
						Evidence:       "ListQueryLoggingConfigs returned zero configs.",
						RemediationCmd: "Enable Route 53 query logging for public zones where DNS visibility is required.",
						Impact:         "Without DNS query logs, investigation of suspicious DNS lookups is harder.",
					})
				}
			}

			records := route53.NewListResourceRecordSetsPaginator(client, &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String(zoneID)})
			for records.HasMorePages() {
				recordPage, err := records.NextPage(ctx)
				if err != nil {
					break
				}
				for _, record := range recordPage.ResourceRecordSets {
					recordName := strings.TrimSuffix(str(record.Name), ".")
					recordID := fmt.Sprintf("%s:%s:%s", zoneID, recordName, record.Type)
					resources = append(resources, resource("Route 53", "Record Set", recordID, recordName, "global", string(record.Type), "dns_record_inventory"))
					if scope == "public" && strings.HasPrefix(recordName, "*.") {
						findings = append(findings, Finding{
							ID:             fmt.Sprintf("SEC-R53-WILDCARD-%s", sanitizeID(recordID)),
							Service:        "Route 53",
							Category:       "SECURITY",
							Severity:       "LOW",
							Title:          "Route 53 Public Wildcard DNS Record",
							Description:    fmt.Sprintf("Public hosted zone '%s' contains wildcard record '%s'.", name, recordName),
							ResourceID:     recordID,
							Evidence:       fmt.Sprintf("Type=%s Name=%s", record.Type, recordName),
							RemediationCmd: "Confirm wildcard DNS is intentional and covered by routing, TLS, monitoring, and ownership controls.",
							Impact:         "Wildcard DNS can accidentally route unexpected hostnames to public endpoints.",
						})
					}
				}
			}
		}
	}

	return findings, resources
}

func cleanHostedZoneID(value string) string {
	return strings.TrimPrefix(value, "/hostedzone/")
}

func auditACMCertificates(ctx context.Context, client *acm.Client, region string) ([]Finding, []ScannedResource) {
	var findings []Finding
	var resources []ScannedResource
	paginator := acm.NewListCertificatesPaginator(client, &acm.ListCertificatesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, resources
		}
		for _, cert := range page.CertificateSummaryList {
			arn := str(cert.CertificateArn)
			name := str(cert.DomainName)
			status := string(cert.Status)
			resources = append(resources, resource("ACM", "Certificate", arn, name, region, status, "expiry", "in_use", "renewal_eligibility"))

			detail, err := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: cert.CertificateArn})
			if err != nil || detail.Certificate == nil {
				continue
			}
			c := detail.Certificate
			if c.NotAfter != nil {
				days := int(time.Until(*c.NotAfter).Hours() / 24)
				if days <= 30 {
					severity := "HIGH"
					if days > 14 {
						severity = "MEDIUM"
					}
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("SEC-ACM-EXPIRY-%s", sanitizeID(arn)),
						Service:        "ACM",
						Category:       "SECURITY",
						Severity:       severity,
						Title:          "ACM Certificate Expires Soon",
						Description:    fmt.Sprintf("Certificate for '%s' expires in %d days.", name, days),
						ResourceID:     arn,
						Evidence:       fmt.Sprintf("NotAfter=%s DaysRemaining=%d", c.NotAfter.Format(time.RFC3339), days),
						RemediationCmd: "Confirm DNS/email validation and renewal eligibility, or replace the certificate before expiry.",
						Impact:         "Expired certificates cause HTTPS outages and user trust failures.",
					})
				}
			}
			if len(c.InUseBy) == 0 {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("SEC-ACM-UNUSED-%s", sanitizeID(arn)),
					Service:        "ACM",
					Category:       "COST",
					Severity:       "LOW",
					Title:          "ACM Certificate Not In Use",
					Description:    fmt.Sprintf("Certificate for '%s' is not associated with an AWS resource.", name),
					ResourceID:     arn,
					Evidence:       "InUseBy is empty.",
					RemediationCmd: "Review whether the certificate is still required before deleting it.",
					Impact:         "Unused certificates create operational clutter and can confuse certificate lifecycle management.",
				})
			}
		}
	}

	return findings, resources
}

func sanitizeID(value string) string {
	value = strings.ReplaceAll(value, ":", "-")
	value = strings.ReplaceAll(value, "/", "-")
	return value
}

func severityCounts(findings []Finding) (critical, high, medium, low int) {
	for _, finding := range findings {
		switch finding.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}
	return
}

func runSimulationScan() Report {
	findings := []Finding{
		{
			ID:             "DEMO-SEC-IAM-ROOT-MFA",
			Service:        "IAM",
			Category:       "SECURITY",
			Severity:       "CRITICAL",
			Title:          "[DEMO] Root Account Multi-Factor Authentication (MFA) Missing",
			Description:    "Simulated finding for dashboard demonstration only.",
			ResourceID:     "arn:aws:iam::000000000000:root",
			Evidence:       "DEMO DATA: credential report mfa_active=false.",
			RemediationCmd: "Enable MFA for the root user in the AWS Console.",
			Impact:         "Demo impact text. Not from a live AWS account.",
		},
		{
			ID:             "DEMO-SEC-EC2-SG",
			Service:        "EC2 / Security Groups",
			Category:       "SECURITY",
			Severity:       "CRITICAL",
			Title:          "[DEMO] SSH Port Exposed to Public Internet",
			Description:    "Simulated finding for dashboard demonstration only.",
			ResourceID:     "sg-demo000000000000",
			Evidence:       "DEMO DATA: Ingress TCP Port=22 Source=0.0.0.0/0.",
			RemediationCmd: "aws ec2 revoke-security-group-ingress --group-id sg-demo000000000000 --protocol tcp --port 22 --cidr 0.0.0.0/0",
			Impact:         "Demo impact text. Not from a live AWS account.",
		},
		{
			ID:             "DEMO-COST-EBS",
			Service:        "EC2 / EBS",
			Category:       "COST",
			Severity:       "MEDIUM",
			Title:          "[DEMO] Orphaned EBS Volume Incurring Costs",
			Description:    "Simulated finding for dashboard demonstration only.",
			ResourceID:     "vol-demo000000000000",
			Evidence:       "DEMO DATA: State=available Size=250GB.",
			RemediationCmd: "aws ec2 delete-volume --volume-id vol-demo000000000000",
			Impact:         "Demo impact text. Not from a live AWS account.",
		},
		{
			ID:             "DEMO-SEC-CF-HTTP",
			Service:        "CloudFront",
			Category:       "SECURITY",
			Severity:       "MEDIUM",
			Title:          "[DEMO] CloudFront Allows HTTP Viewer Requests",
			Description:    "Simulated finding for dashboard demonstration only.",
			ResourceID:     "EDFDEMO000000",
			Evidence:       "DEMO DATA: ViewerProtocolPolicy=allow-all.",
			RemediationCmd: "Update viewer protocol policy to redirect-to-https.",
			Impact:         "Demo impact text. Not from a live AWS account.",
		},
		{
			ID:             "DEMO-SEC-ACM-EXPIRY",
			Service:        "ACM",
			Category:       "SECURITY",
			Severity:       "HIGH",
			Title:          "[DEMO] ACM Certificate Expires Soon",
			Description:    "Simulated finding for dashboard demonstration only.",
			ResourceID:     "arn:aws:acm:demo:000000000000:certificate/demo",
			Evidence:       "DEMO DATA: DaysRemaining=10.",
			RemediationCmd: "Confirm validation and renew or replace the certificate.",
			Impact:         "Demo impact text. Not from a live AWS account.",
		},
		{
			ID:             "DEMO-SEC-ELB-NO-HTTPS",
			Service:        "ELBv2",
			Category:       "SECURITY",
			Severity:       "HIGH",
			Title:          "[DEMO] Internet-Facing Load Balancer Has No HTTPS Listener",
			Description:    "Simulated finding for dashboard demonstration only.",
			ResourceID:     "arn:aws:elasticloadbalancing:demo:000000000000:loadbalancer/app/demo/123",
			Evidence:       "DEMO DATA: Scheme=internet-facing HTTPSListener=false.",
			RemediationCmd: "Add an HTTPS listener with an ACM certificate.",
			Impact:         "Demo impact text. Not from a live AWS account.",
		},
		{
			ID:             "DEMO-SEC-TG-UNHEALTHY",
			Service:        "ELBv2",
			Category:       "SECURITY",
			Severity:       "MEDIUM",
			Title:          "[DEMO] Target Group Has Unhealthy Targets",
			Description:    "Simulated finding for dashboard demonstration only.",
			ResourceID:     "arn:aws:elasticloadbalancing:demo:000000000000:targetgroup/demo/123",
			Evidence:       "DEMO DATA: UnhealthyTargets=1 TotalTargets=2.",
			RemediationCmd: "Investigate health checks, ports, security groups, and application health.",
			Impact:         "Demo impact text. Not from a live AWS account.",
		},
		{
			ID:             "DEMO-COST-NAT-REVIEW",
			Service:        "EC2 / VPC",
			Category:       "COST",
			Severity:       "LOW",
			Title:          "[DEMO] NAT Gateway Running Cost Review",
			Description:    "Simulated finding for dashboard demonstration only.",
			ResourceID:     "nat-demo000000000000",
			Evidence:       "DEMO DATA: State=available EstimatedBaseMonthlyCost=$32.40.",
			RemediationCmd: "Review NAT Gateway traffic and route table usage.",
			Impact:         "Demo impact text. Not from a live AWS account.",
		},
		{
			ID:             "DEMO-SEC-R53-WILDCARD",
			Service:        "Route 53",
			Category:       "SECURITY",
			Severity:       "LOW",
			Title:          "[DEMO] Route 53 Public Wildcard DNS Record",
			Description:    "Simulated finding for dashboard demonstration only.",
			ResourceID:     "ZDEMO:*.demo.automyx.tech:A",
			Evidence:       "DEMO DATA: Type=A Name=*.demo.automyx.tech.",
			RemediationCmd: "Confirm wildcard DNS is intentional.",
			Impact:         "Demo impact text. Not from a live AWS account.",
		},
	}

	critical, high, medium, low := severityCounts(findings)
	resources := []ScannedResource{
		resource("IAM", "Root Account", "arn:aws:iam::000000000000:root", "<root_account>", "global", "DEMO", "root_mfa_credential_report"),
		resource("IAM", "User", "arn:aws:iam::000000000000:user/demo-admin", "demo-admin", "global", "DEMO", "access_key_age"),
		resource("S3", "Bucket", "arn:aws:s3:::demo-audit-bucket", "demo-audit-bucket", "global", "DEMO", "public_access_block", "default_encryption", "versioning"),
		resource("EC2 / VPC", "VPC", "vpc-demo000000000000", "demo-vpc", "demo", "DEMO", "cidr_block", "default_vpc_flag"),
		resource("EC2 / VPC", "Subnet", "subnet-demo000000000000", "demo-public-subnet", "demo", "available", "map_public_ip_on_launch", "available_ip_count", "vpc_association"),
		resource("EC2 / VPC", "Route Table", "rtb-demo000000000000", "demo-public-rt", "demo", "DEMO", "internet_gateway_default_route", "subnet_associations"),
		resource("EC2 / VPC", "Network ACL", "acl-demo000000000000", "demo-public-acl", "demo", "DEMO", "public_inbound_management_ports", "public_inbound_database_ports"),
		resource("EC2 / Security Groups", "Security Group", "sg-demo000000000000", "demo-ssh", "demo", "DEMO", "public_ingress_management_ports"),
		resource("EC2 / Instances", "Instance", "i-demo000000000000", "demo-linux", "demo", "running", "state", "public_ip"),
		resource("EC2 / EBS", "Volume", "vol-demo000000000000", "vol-demo000000000000", "demo", "available", "attachment_state", "volume_size", "volume_type"),
		resource("EC2 / Elastic IP", "Elastic IP", "eipalloc-demo000000000000", "203.0.113.10", "demo", "unassociated", "association_state", "public_ipv4_charge"),
		resource("EC2 / VPC", "NAT Gateway", "nat-demo000000000000", "demo-nat", "demo", "available", "state", "subnet", "hourly_cost_awareness"),
		resource("ELBv2", "Load Balancer", "arn:aws:elasticloadbalancing:demo:000000000000:loadbalancer/app/demo/123", "demo-alb", "demo", "active", "scheme", "listeners", "tls_termination", "target_groups"),
		resource("ELBv2", "Target Group", "arn:aws:elasticloadbalancing:demo:000000000000:targetgroup/demo/123", "demo-tg", "demo", "HTTP", "registered_targets", "target_health", "health_check"),
		resource("Auto Scaling", "Auto Scaling Group", "arn:aws:autoscaling:demo:000000000000:autoScalingGroup:demo:autoScalingGroupName/demo-asg", "demo-asg", "demo", "CHECKED", "desired_capacity", "min_max_capacity", "instance_health"),
		resource("RDS", "DB Instance", "arn:aws:rds:demo:000000000000:db:demo-db", "demo-db", "demo", "available", "storage_encryption", "public_accessibility", "backup_retention"),
		resource("CloudFront", "Distribution", "EDFDEMO000000", "d111111abcdef8.cloudfront.net", "global", "Deployed", "viewer_protocol_policy", "custom_certificate", "waf_association"),
		resource("Route 53", "Hosted Zone", "ZDEMO", "demo.automyx.tech", "global", "public", "record_sets", "query_logging", "wildcard_records"),
		resource("Route 53", "Record Set", "ZDEMO:*.demo.automyx.tech:A", "*.demo.automyx.tech", "global", "A", "dns_record_inventory"),
		resource("ACM", "Certificate", "arn:aws:acm:demo:000000000000:certificate/demo", "demo.automyx.tech", "demo", "ISSUED", "expiry", "in_use", "renewal_eligibility"),
	}
	resources = attachFindingCounts(resources, findings)

	return Report{
		Metadata: ScanMetadata{
			Tool:      "AutoMyx CloudGuard CLI",
			Version:   "1.1.0",
			ScanTime:  time.Now().UTC().Format(time.RFC3339),
			AccountID: "000000000000",
			Region:    "demo",
			Status:    "COMPLETED",
			Mode:      "DEMO",
		},
		Summary: Summary{
			TotalChecked:             len(resources),
			TotalFindings:            len(findings),
			Critical:                 critical,
			High:                     high,
			Medium:                   medium,
			Low:                      low,
			CostSavingsMonthly:       20.00,
			ServicesScanned:          servicesScannedCount(),
			ServicesDeployedInRegion: servicesDeployedInRegion(resources, "demo"),
		},
		Findings:  findings,
		Resources: resources,
	}
}
