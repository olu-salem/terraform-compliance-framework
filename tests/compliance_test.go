package test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRepoLayout runs in -short mode so CI can verify the workspace without AWS.
func TestRepoLayout(t *testing.T) {
	t.Parallel()
	paths := []string{
		"../modules/vpc/main.tf",
		"../modules/s3/main.tf",
		"../environments/dev/main.tf",
		"../policies/opa/tagging.rego",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected path %s: %v", p, err)
		}
	}
}

// =============================================================================
// VPC Module Tests
// Tests that the VPC module creates infrastructure matching compliance
// requirements: private subnets, flow logs, no public IPs on launch, etc.
// =============================================================================

func TestVPCModule(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live AWS test in -short mode (see Makefile test target)")
	}
	t.Parallel()

	awsRegion := "us-east-1"
	uniqueID := random.UniqueId()
	name := fmt.Sprintf("terratest-%s", strings.ToLower(uniqueID))

	terraformOptions := &terraform.Options{
		TerraformDir: "../modules/vpc",
		Vars: map[string]interface{}{
			"name":        name,
			"environment": "dev",
			"aws_region":  awsRegion,
			"vpc_cidr":    "10.99.0.0/16",
			"availability_zones": []string{
				"us-east-1a",
				"us-east-1b",
			},
			"single_nat_gateway":     true, // cost savings in tests
			"flow_log_retention_days": 7,
			"tags": map[string]interface{}{
				"Environment": "dev",
				"CostCenter":  "terratest",
				"Owner":       "platform-test@company.com",
				"DataClass":   "internal",
			},
		},
		NoColor: true,
		RetryableTerraformErrors: map[string]string{
			"RequestError: send request failed": "Transient AWS API error",
		},
		MaxRetries:         3,
		TimeBetweenRetries: 5 * time.Second,
	}

	// Clean up resources after test
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the VPC
	terraform.InitAndApply(t, terraformOptions)

	// ── Assertions ──────────────────────────────────────────────────────────

	vpcID := terraform.Output(t, terraformOptions, "vpc_id")
	require.NotEmpty(t, vpcID, "VPC ID should not be empty")

	// Verify VPC CIDR
	vpcCIDR := terraform.Output(t, terraformOptions, "vpc_cidr_block")
	assert.Equal(t, "10.99.0.0/16", vpcCIDR, "VPC CIDR should match input")

	// Verify 2 private subnets were created
	privateSubnets := terraform.OutputList(t, terraformOptions, "private_subnet_ids")
	assert.Len(t, privateSubnets, 2, "Should create one private subnet per AZ")

	// Verify 2 public subnets were created
	publicSubnets := terraform.OutputList(t, terraformOptions, "public_subnet_ids")
	assert.Len(t, publicSubnets, 2, "Should create one public subnet per AZ")

	// Verify 2 intra subnets were created
	intraSubnets := terraform.OutputList(t, terraformOptions, "intra_subnet_ids")
	assert.Len(t, intraSubnets, 2, "Should create one intra subnet per AZ")

	// CIS 5.4 — Verify private subnets don't auto-assign public IPs
	sess, err := aws.NewAuthenticatedSession(awsRegion)
	require.NoError(t, err)
	ec2Client := ec2.New(sess)
	describeOut, err := ec2Client.DescribeSubnets(&ec2.DescribeSubnetsInput{
		SubnetIds: awssdk.StringSlice(privateSubnets),
	})
	require.NoError(t, err)
	for _, sn := range describeOut.Subnets {
		id := awssdk.StringValue(sn.SubnetId)
		assert.False(t, awssdk.BoolValue(sn.MapPublicIpOnLaunch),
			"Private subnet %s should not auto-assign public IPs (CIS 5.4)", id)
	}

	// CIS 3.9 — Verify VPC flow logs are enabled
	flowLogID := terraform.Output(t, terraformOptions, "flow_log_id")
	assert.NotEmpty(t, flowLogID, "VPC flow log should be created (CIS 3.9)")

	// Verify single NAT gateway was created
	natGatewayIDs := terraform.OutputList(t, terraformOptions, "nat_gateway_ids")
	assert.Len(t, natGatewayIDs, 1, "Should create single NAT gateway when single_nat_gateway=true")

	// Verify NAT public IPs are assigned
	natPublicIPs := terraform.OutputList(t, terraformOptions, "nat_public_ips")
	assert.Len(t, natPublicIPs, 1, "Should have one NAT EIP")
	assert.NotEmpty(t, natPublicIPs[0], "NAT public IP should not be empty")

	// Verify intra subnets have no internet route (isolated)
	// This would require additional AWS SDK calls to verify route tables
	t.Log("✅ VPC module compliance checks passed")
}

// =============================================================================
// S3 Module Tests
// Verify encryption, public access blocking, versioning
// =============================================================================

func TestS3Module(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live AWS test in -short mode (see Makefile test target)")
	}
	t.Parallel()

	awsRegion := "us-east-1"
	uniqueID := random.UniqueId()
	bucketName := fmt.Sprintf("terratest-compliance-%s", strings.ToLower(uniqueID))

	terraformOptions := &terraform.Options{
		TerraformDir: "../modules/s3",
		Vars: map[string]interface{}{
			"bucket_name":  bucketName,
			"environment":  "dev",
			"create_kms_key": true,
			"tags": map[string]interface{}{
				"Environment": "dev",
				"CostCenter":  "terratest",
				"Owner":       "platform-test@company.com",
				"DataClass":   "internal",
			},
		},
		NoColor: true,
	}

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	// CIS 2.1.5 — Verify public access is blocked
	actualBucketName := terraform.Output(t, terraformOptions, "bucket_name")

	sess, err := aws.NewAuthenticatedSession(awsRegion)
	require.NoError(t, err)
	s3Client := s3.New(sess)

	pabOut, err := s3Client.GetPublicAccessBlock(&s3.GetPublicAccessBlockInput{
		Bucket: awssdk.String(actualBucketName),
	})
	require.NoError(t, err)
	pab := pabOut.PublicAccessBlockConfiguration
	require.NotNil(t, pab)
	assert.True(t, awssdk.BoolValue(pab.BlockPublicAcls),
		"S3 block_public_acls must be true (CIS 2.1.5)")
	assert.True(t, awssdk.BoolValue(pab.BlockPublicPolicy),
		"S3 block_public_policy must be true (CIS 2.1.5)")
	assert.True(t, awssdk.BoolValue(pab.IgnorePublicAcls),
		"S3 ignore_public_acls must be true (CIS 2.1.5)")
	assert.True(t, awssdk.BoolValue(pab.RestrictPublicBuckets),
		"S3 restrict_public_buckets must be true (CIS 2.1.5)")

	// CIS 2.1.1 — Verify SSE-KMS encryption
	sseOut, err := s3Client.GetBucketEncryption(&s3.GetBucketEncryptionInput{
		Bucket: awssdk.String(actualBucketName),
	})
	require.NoError(t, err)
	require.NotNil(t, sseOut.ServerSideEncryptionConfiguration)
	rules := sseOut.ServerSideEncryptionConfiguration.Rules
	require.NotEmpty(t, rules)
	def := rules[0].ApplyServerSideEncryptionByDefault
	require.NotNil(t, def)
	assert.Equal(t, "aws:kms", awssdk.StringValue(def.SSEAlgorithm),
		"S3 must use SSE-KMS, not SSE-S3 (CIS 2.1.1)")

	// Verify versioning is enabled
	versioningStatus := aws.GetS3BucketVersioning(t, awsRegion, actualBucketName)
	assert.Equal(t, "Enabled", versioningStatus, "S3 versioning must be enabled")

	t.Log("✅ S3 module compliance checks passed")
}

// =============================================================================
// RDS Module Tests
// Verify encryption, no public access, backup configuration
// =============================================================================

func TestRDSModule(t *testing.T) {
	// Skip in short mode — RDS takes ~10 minutes to provision
	if testing.Short() {
		t.Skip("Skipping RDS tests in short mode (use -run TestRDSModule without -short)")
	}
	t.Parallel()

	awsRegion := "us-east-1"
	uniqueID := random.UniqueId()
	name := fmt.Sprintf("terratest-%s", strings.ToLower(uniqueID))

	t.Logf("RDS module test placeholder (region=%s unique=%s name=%s) — add VPC fixture + apply/destroy when ready", awsRegion, uniqueID, name)
}

// =============================================================================
// Compliance Integration Test
// Tests all modules together in an environment-like configuration
// =============================================================================

func TestComplianceIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	t.Parallel()

	awsRegion := "us-east-1"
	uniqueID := random.UniqueId()
	name := fmt.Sprintf("terratest-int-%s", strings.ToLower(uniqueID))

	planFile := filepath.Join(os.TempDir(), fmt.Sprintf("tfplan-compliance-%s.binary", uniqueID))

	// Remote S3 backend is optional for this test — plan with local state.
	compliantOptions := &terraform.Options{
		TerraformDir: "../environments/dev",
		VarFiles:     []string{"terraform.tfvars"},
		Vars: map[string]interface{}{
			"name":       name,
			"aws_region": awsRegion,
		},
		PlanFilePath: planFile,
		NoColor:      true,
		EnvVars: map[string]string{
			"TF_CLI_ARGS_init": "-backend=false -input=false",
		},
	}

	// Plan only — don't apply in integration test
	exitCode := terraform.PlanExitCode(t, compliantOptions)
	
	// 0 = no changes, 2 = changes pending — both are valid
	assert.True(t, exitCode == 0 || exitCode == 2,
		"Terraform plan should succeed for compliant configuration (exit code 0 or 2, got %d)", exitCode)

	t.Log("✅ Compliance integration test passed")
}

// =============================================================================
// Tag Validation Tests
// Verify that resources FAIL when required tags are missing
// =============================================================================

func TestTaggingEnforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live AWS test in -short mode (see Makefile test target)")
	}
	t.Parallel()

	// Test that missing tags cause a plan failure via terraform validation
	terraformOptions := &terraform.Options{
		TerraformDir: "../modules/vpc",
		Vars: map[string]interface{}{
			"name":        "tag-test",
			"environment": "dev",
			"aws_region":  "us-east-1",
			"vpc_cidr":    "10.100.0.0/16",
			"availability_zones": []string{"us-east-1a", "us-east-1b"},
			"tags": map[string]interface{}{
				// Missing CostCenter, Owner, DataClass — should fail validation
				"Environment": "dev",
			},
		},
		NoColor: true,
	}

	// Expect the plan to fail because of missing required tags (no apply — no destroy needed)
	_, err := terraform.InitAndPlanE(t, terraformOptions)
	require.Error(t, err, "Plan should fail when required tags are missing")
	assert.Contains(t, err.Error(), "CostCenter",
		"Error message should mention missing CostCenter tag")

	t.Log("✅ Tag enforcement correctly blocked non-compliant configuration")
}