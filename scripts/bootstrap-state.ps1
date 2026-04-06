#Requires -Version 5.1
<#
.SYNOPSIS
  Bootstrap S3 + KMS for Terraform remote state (Windows / PowerShell). Locking: S3 use_lockfile.

.DESCRIPTION
  PowerShell equivalent of bootstrap-state.sh. Run once per account/environment
  before `terraform init` with S3 backend.

.EXAMPLE
  .\bootstrap-state.ps1 -AccountId 123456789012 -Region us-east-1 -Env dev
#>
param(
    [Parameter(Mandatory = $true)][string]$AccountId,
    [string]$Region = "us-east-1",
    [Parameter(Mandatory = $true)][ValidateSet("dev", "staging", "prod")][string]$Env
)

$ErrorActionPreference = "Stop"

$BucketName = "enterprise-tfstate-$Env-$AccountId"
$KmsAlias = "alias/enterprise-tfstate-$Env"

Write-Host "Terraform State Backend Bootstrap"
Write-Host "  Account: $AccountId  Region: $Region  Env: $Env"
Write-Host "  Bucket:  $BucketName"

# --- KMS ---
aws kms describe-key --key-id $KmsAlias --region $Region 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    $KmsKeyArn = aws kms describe-key --key-id $KmsAlias --region $Region --query "KeyMetadata.Arn" --output text
    Write-Host "KMS key already exists: $KmsKeyArn"
}
else {
    $create = aws kms create-key `
        --description "Terraform state encryption key - $Env" `
        --region $Region `
        --tags "TagKey=Environment,TagValue=$Env" "TagKey=ManagedBy,TagValue=bootstrap-script" `
        --query "KeyMetadata.KeyId" --output text
    if (-not $create) { throw "kms create-key failed" }

    aws kms create-alias --alias-name $KmsAlias --target-key-id $create --region $Region | Out-Null
    aws kms enable-key-rotation --key-id $create --region $Region | Out-Null

    $KmsKeyArn = aws kms describe-key --key-id $create --region $Region --query "KeyMetadata.Arn" --output text
    Write-Host "Created KMS key: $KmsKeyArn"
}

# --- S3 bucket ---
aws s3api head-bucket --bucket $BucketName --region $Region 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    if ($Region -eq "us-east-1") {
        aws s3api create-bucket --bucket $BucketName --region $Region | Out-Null
    }
    else {
        aws s3api create-bucket --bucket $BucketName --region $Region `
            --create-bucket-configuration "LocationConstraint=$Region" | Out-Null
    }

    aws s3api put-public-access-block --bucket $BucketName --public-access-block-configuration `
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" | Out-Null

    aws s3api put-bucket-versioning --bucket $BucketName --versioning-configuration Status=Enabled | Out-Null

    $encJson = "{`"Rules`":[{`"ApplyServerSideEncryptionByDefault`":{`"SSEAlgorithm`":`"aws:kms`",`"KMSMasterKeyID`":`"$KmsKeyArn`"},`"BucketKeyEnabled`":true}]}"
    aws s3api put-bucket-encryption --bucket $BucketName --server-side-encryption-configuration $encJson | Out-Null

    $policy = @"
{"Version":"2012-10-17","Statement":[{"Sid":"DenyHTTP","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::$BucketName","arn:aws:s3:::$BucketName/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}
"@
    aws s3api put-bucket-policy --bucket $BucketName --policy $policy | Out-Null
    Write-Host "Created bucket: $BucketName"
}
else {
    Write-Host "Bucket already exists: $BucketName"
}

Write-Host ""
Write-Host "Bootstrap complete. Use with terraform init:"
Write-Host "  terraform init \"
Write-Host "    -backend-config=`"bucket=$BucketName`" \"
Write-Host "    -backend-config=`"key=$Env/terraform.tfstate`" \"
Write-Host "    -backend-config=`"region=$Region`" \"
Write-Host "    -backend-config=`"use_lockfile=true`" \"
Write-Host "    -backend-config=`"kms_key_id=$KmsKeyArn`" \"
Write-Host "    -backend-config=`"encrypt=true`""
