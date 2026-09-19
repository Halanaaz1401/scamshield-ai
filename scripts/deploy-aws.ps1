# ScamShield AI - Production AWS Zero-Cost Deployment Script
# Deploys API Gateway + Lambda + DynamoDB (PAY_PER_REQUEST) under AWS Free Tier

param(
    [string]$Region = "us-east-1",
    [string]$StackName = "scamshield-ai",
    [string]$GeminiApiKey = "",
    [string]$AllowedOrigin = "*"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path "$PSScriptRoot\.."

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " ScamShield AI - AWS Free-Tier Serverless Deployment" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify AWS credentials
Write-Host "[1/5] Checking AWS authentication..." -ForegroundColor Green
$IdentityJson = cmd /c "aws sts get-caller-identity --output json 2>nul"
if ($LASTEXITCODE -ne 0 -or -not $IdentityJson) {
    Write-Host ""
    Write-Host ">>> ERROR: AWS Credentials not configured!" -ForegroundColor Red
    Write-Host "Please configure your AWS credentials before running deployment:" -ForegroundColor Yellow
    Write-Host "  Option A: Run 'aws configure' and enter your AWS Access Key, Secret Key, and Region." -ForegroundColor White
    Write-Host "  Option B: In your shell, set environment variables:" -ForegroundColor White
    Write-Host "    `$env:AWS_ACCESS_KEY_ID = 'your_access_key'" -ForegroundColor Cyan
    Write-Host "    `$env:AWS_SECRET_ACCESS_KEY = 'your_secret_key'" -ForegroundColor Cyan
    Write-Host "    `$env:AWS_DEFAULT_REGION = '$Region'" -ForegroundColor Cyan
    exit 1
}
$CallerIdentity = $IdentityJson | ConvertFrom-Json
Write-Host " Authenticated to AWS Account: $($CallerIdentity.Account) as $($CallerIdentity.Arn)" -ForegroundColor Green

# 2. Build Lambda package
Write-Host "[2/5] Building Lambda artifact..." -ForegroundColor Green
& powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\build-lambda.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host ">>> ERROR: Lambda artifact build failed (exit code $LASTEXITCODE)." -ForegroundColor Red
    Write-Host "Review the output above for pip or filesystem errors." -ForegroundColor Yellow
    exit 1
}

# 3. Deploy via AWS SAM
Write-Host "[3/5] Deploying CloudFormation stack '$StackName' to region '$Region'..." -ForegroundColor Green

$DeployParams = @(
    "deploy",
    "--template-file", "$Root\.aws-sam\build\template.yaml",
    "--stack-name", $StackName,
    "--region", $Region,
    "--capabilities", "CAPABILITY_IAM",
    "--resolve-s3",
    "--no-fail-on-empty-changeset",
    "--parameter-overrides",
    "AllowedOrigin=$AllowedOrigin"
)

if ($GeminiApiKey) {
    $DeployParams += "GeminiApiKey=$GeminiApiKey"
}

sam @DeployParams
$SamExitCode = $LASTEXITCODE

if ($SamExitCode -ne 0) {
    Write-Host ""
    Write-Host ">>> DEPLOYMENT FAILED: AWS SAM deploy exited with code $SamExitCode." -ForegroundColor Red
    Write-Host ""
    Write-Host "Common causes:" -ForegroundColor Yellow
    Write-Host "  1. AWS Organizations Service Control Policy (SCP) is blocking CloudFormation." -ForegroundColor White
    Write-Host "     The SCP on your AWS Organization explicitly denies cloudformation:CreateChangeSet" -ForegroundColor White
    Write-Host "     and related actions on this account. This is an AWS administrator-level restriction." -ForegroundColor White
    Write-Host "     --> ACTION REQUIRED: Ask your AWS Organization administrator to allow the" -ForegroundColor Cyan
    Write-Host "         permissions listed below for account $($CallerIdentity.Account)." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  2. Insufficient IAM permissions on the assumed role." -ForegroundColor White
    Write-Host "     Current identity: $($CallerIdentity.Arn)" -ForegroundColor White
    Write-Host ""
    Write-Host "Required IAM actions for SAM deployment (ask your AWS admin to allow these):" -ForegroundColor Yellow
    Write-Host "  cloudformation:CreateChangeSet" -ForegroundColor White
    Write-Host "  cloudformation:DescribeChangeSet" -ForegroundColor White
    Write-Host "  cloudformation:ExecuteChangeSet" -ForegroundColor White
    Write-Host "  cloudformation:DescribeStacks" -ForegroundColor White
    Write-Host "  cloudformation:DescribeStackEvents" -ForegroundColor White
    Write-Host "  cloudformation:GetTemplateSummary" -ForegroundColor White
    Write-Host "  cloudformation:CreateStack" -ForegroundColor White
    Write-Host "  cloudformation:UpdateStack" -ForegroundColor White
    Write-Host "  cloudformation:DeleteStack (optional, for teardown)" -ForegroundColor White
    Write-Host "  s3:CreateBucket, s3:PutObject, s3:GetObject (SAM managed S3 bucket)" -ForegroundColor White
    Write-Host "  iam:CreateRole, iam:AttachRolePolicy, iam:PutRolePolicy, iam:PassRole" -ForegroundColor White
    Write-Host "  lambda:CreateFunction, lambda:UpdateFunctionCode, lambda:UpdateFunctionConfiguration" -ForegroundColor White
    Write-Host "  lambda:AddPermission, lambda:GetFunction" -ForegroundColor White
    Write-Host "  apigateway:POST, apigateway:PUT, apigateway:PATCH, apigateway:GET, apigateway:DELETE" -ForegroundColor White
    Write-Host "  dynamodb:CreateTable, dynamodb:DescribeTable, dynamodb:UpdateTimeToLive" -ForegroundColor White
    Write-Host ""
    Write-Host "The Lambda artifact and template are valid. This is an AWS account permission issue." -ForegroundColor Green
    Write-Host "No application code changes are needed." -ForegroundColor Green
    exit 1
}

# 4. Extract API Gateway outputs
Write-Host "[4/5] Retrieving API Gateway endpoint URLs..." -ForegroundColor Green
$DescribeOutput = aws cloudformation describe-stacks --stack-name $StackName --region $Region --output json 2>&1
$DescribeExitCode = $LASTEXITCODE

if ($DescribeExitCode -ne 0) {
    Write-Host ""
    Write-Host ">>> ERROR: Could not retrieve CloudFormation stack outputs (exit code $DescribeExitCode)." -ForegroundColor Red
    Write-Host "Stack '$StackName' may not exist or you may lack cloudformation:DescribeStacks permission." -ForegroundColor Yellow
    Write-Host "Error detail: $DescribeOutput" -ForegroundColor DarkGray
    exit 1
}

$StackInfo = $DescribeOutput | ConvertFrom-Json

if (-not $StackInfo -or -not $StackInfo.Stacks -or $StackInfo.Stacks.Count -eq 0) {
    Write-Host ""
    Write-Host ">>> ERROR: Stack '$StackName' not found in region '$Region'." -ForegroundColor Red
    Write-Host "The deployment may have rolled back. Check the CloudFormation Console for details." -ForegroundColor Yellow
    exit 1
}

$Outputs = $StackInfo.Stacks[0].Outputs

if (-not $Outputs) {
    Write-Host ""
    Write-Host ">>> ERROR: Stack '$StackName' has no outputs. The stack may still be deploying or failed." -ForegroundColor Red
    exit 1
}

$ApiUrl     = ($Outputs | Where-Object { $_.OutputKey -eq "ApiUrl"     }).OutputValue
$AnalyzeUrl = ($Outputs | Where-Object { $_.OutputKey -eq "AnalyzeUrl" }).OutputValue
$HealthUrl  = ($Outputs | Where-Object { $_.OutputKey -eq "HealthUrl"  }).OutputValue

if (-not $ApiUrl) {
    Write-Host ">>> ERROR: ApiUrl output not found in stack outputs." -ForegroundColor Red
    exit 1
}

Write-Host ">>> API Gateway Base URL: $ApiUrl"    -ForegroundColor Cyan
Write-Host ">>> POST /analyze URL:    $AnalyzeUrl" -ForegroundColor Cyan
Write-Host ">>> GET /health URL:      $HealthUrl"  -ForegroundColor Cyan

# 5. Smoke test
Write-Host "[5/5] Performing live endpoint smoke test..." -ForegroundColor Green
try {
    $HealthRes = Invoke-RestMethod -Uri $HealthUrl -Method Get -TimeoutSec 15
    Write-Host " GET /health test: SUCCESS (Status: $($HealthRes.status))" -ForegroundColor Green
} catch {
    Write-Host " Warning: Health check endpoint did not respond immediately. Lambda may still be cold-starting." -ForegroundColor Yellow
    Write-Host " Try manually: Invoke-RestMethod -Uri '$HealthUrl' -Method Get" -ForegroundColor White
}

# Save frontend production config
$FrontendEnvPath = Join-Path $Root "frontend\.env.production"
Set-Content -Path $FrontendEnvPath -Value "NEXT_PUBLIC_API_BASE_URL=$ApiUrl"
Write-Host " Saved production API URL to frontend\.env.production" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AWS Backend Deployment Complete!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Next Step: Deploy Frontend to AWS Amplify Hosting:" -ForegroundColor Yellow
Write-Host "1. In AWS Amplify Console: Choose 'Host web app' -> Connect GitHub repo." -ForegroundColor White
Write-Host "2. In Amplify Environment Variables, set: NEXT_PUBLIC_API_BASE_URL = $ApiUrl" -ForegroundColor White
Write-Host "3. Amplify will build and assign your free public HTTPS domain!" -ForegroundColor White
