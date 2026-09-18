# ScamShield AI - Serverless Lambda Packaging Script for Windows / Cross-Platform
# Builds production-ready Linux x86_64 Python 3.12 Lambda artifact without requiring local Docker

$ErrorActionPreference = "Stop"

$Root = Resolve-Path "$PSScriptRoot\.."
$BackendDir = Join-Path $Root "backend"
$BuildDir = Join-Path $Root ".aws-sam\build\AnalyzeFunction"
$TemplateSrc = Join-Path $Root "infrastructure\template.yaml"
$TemplateDest = Join-Path $Root ".aws-sam\build\template.yaml"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " ScamShield AI - Packaging AWS Lambda Artifact" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Ensure clean build target directory
if (Test-Path $BuildDir) {
    Write-Host "[1/4] Cleaning existing build directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BuildDir
}
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null

# 2. Install Linux Python 3.12 binary wheels
Write-Host "[2/4] Downloading and installing Linux x86_64 Python 3.12 dependencies..." -ForegroundColor Green
$ReqFile = Join-Path $BackendDir "requirements.txt"
pip install `
    --platform manylinux2014_x86_64 `
    --implementation cp `
    --python-version 3.12 `
    --only-binary=:all: `
    --target $BuildDir `
    -r $ReqFile

# 3. Copy application source code
Write-Host "[3/4] Copying backend/src into Lambda package..." -ForegroundColor Green
$SrcDir = Join-Path $BackendDir "src"
$DestSrc = Join-Path $BuildDir "src"
Copy-Item -Recurse -Force $SrcDir $DestSrc

# 4. Prepare SAM build template
Write-Host "[4/4] Generating deployment template at $TemplateDest..." -ForegroundColor Green
$TemplateContent = Get-Content $TemplateSrc -Raw
# Replace CodeUri: ../backend/ with CodeUri: AnalyzeFunction
$BuiltTemplate = $TemplateContent -replace 'CodeUri:\s*\.\./backend/?', 'CodeUri: AnalyzeFunction'
Set-Content -Path $TemplateDest -Value $BuiltTemplate -Encoding UTF8

Write-Host ""
Write-Host ">>> Lambda package successfully built in: $BuildDir" -ForegroundColor Green
Write-Host ">>> Deployment template generated: $TemplateDest" -ForegroundColor Green
Write-Host ">>> Ready for zero-cost deployment via: sam deploy --template-file .aws-sam/build/template.yaml" -ForegroundColor Cyan
