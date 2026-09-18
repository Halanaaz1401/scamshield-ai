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

# 4. Extract API Gateway outputs
Write-Host "[4/5] Retrieving API Gateway endpoint URLs..." -ForegroundColor Green
$StackInfo = aws cloudformation describe-stacks --stack-name $StackName --region $Region --output json | ConvertFrom-Json
$Outputs = $StackInfo.Stacks[0].Outputs

$ApiUrl = ($Outputs | Where-Object { $_.OutputKey -eq "ApiUrl" }).OutputValue
$AnalyzeUrl = ($Outputs | Where-Object { $_.OutputKey -eq "AnalyzeUrl" }).OutputValue
$HealthUrl = ($Outputs | Where-Object { $_.OutputKey -eq "HealthUrl" }).OutputValue

Write-Host ">>> API Gateway Base URL: $ApiUrl" -ForegroundColor Cyan
Write-Host ">>> POST /analyze URL:    $AnalyzeUrl" -ForegroundColor Cyan
Write-Host ">>> GET /health URL:      $HealthUrl" -ForegroundColor Cyan

# Smoke test
Write-Host "[5/5] Performing live endpoint smoke test..." -ForegroundColor Green
try {
    $HealthRes = Invoke-RestMethod -Uri $HealthUrl -Method Get -TimeoutSec 10
    Write-Host " GET /health test: SUCCESS (Status: $($HealthRes.status))" -ForegroundColor Green
} catch {
    Write-Host " Warning: Health check endpoint did not respond immediately: $_" -ForegroundColor Yellow
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
