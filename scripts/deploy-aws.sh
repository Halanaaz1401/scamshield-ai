#!/usr/bin/env bash
# ScamShield AI - Production AWS Zero-Cost Deployment Script (Linux/macOS)
set -euo pipefail

REGION="${1:-us-east-1}"
STACK_NAME="${2:-scamshield-ai}"
ALLOWED_ORIGIN="${3:-*}"
GEMINI_KEY="${4:-}"

echo "=========================================================="
echo " ScamShield AI - AWS Free-Tier Serverless Deployment"
echo "=========================================================="

# 1. Check AWS credentials
echo "[1/4] Checking AWS authentication..."
if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "ERROR: AWS credentials not configured. Please run 'aws configure' first." >&2
    exit 1
fi

# 2. Build Lambda artifact
echo "[2/4] Packaging Lambda artifact..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/.aws-sam/build/AnalyzeFunction"

mkdir -p "$BUILD_DIR"
pip install \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --python-version 3.12 \
    --only-binary=:all: \
    --target "$BUILD_DIR" \
    -r "$ROOT_DIR/backend/requirements.txt"

cp -r "$ROOT_DIR/backend/src" "$BUILD_DIR/src"
mkdir -p "$ROOT_DIR/.aws-sam/build"
sed 's|CodeUri: \.\./backend/|CodeUri: AnalyzeFunction|g' "$ROOT_DIR/infrastructure/template.yaml" > "$ROOT_DIR/.aws-sam/build/template.yaml"

# 3. Deploy SAM Stack
echo "[3/4] Deploying CloudFormation stack '$STACK_NAME' to '$REGION'..."
DEPLOY_CMD=(sam deploy \
    --template-file "$ROOT_DIR/.aws-sam/build/template.yaml" \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --capabilities CAPABILITY_IAM \
    --resolve-s3 \
    --no-fail-on-empty-changeset \
    --parameter-overrides "AllowedOrigin=$ALLOWED_ORIGIN")

if [ -n "$GEMINI_KEY" ]; then
    DEPLOY_CMD+=("GeminiApiKey=$GEMINI_KEY")
fi

"${DEPLOY_CMD[@]}"

# 4. Extract API Gateway Output
echo "[4/4] Extracting API Gateway URL..."
API_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text)
echo ">>> Live API Gateway URL: $API_URL"

echo "NEXT_PUBLIC_API_BASE_URL=$API_URL" > "$ROOT_DIR/frontend/.env.production"
echo "Saved production API URL to frontend/.env.production"
echo "Ready for AWS Amplify frontend deployment!"
