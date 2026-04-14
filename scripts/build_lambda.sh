#!/usr/bin/env bash
# Build a Lambda deployment package for PipelineGuard.
#
# Output: dist/pipelineguard-lambda.zip
#
# Usage:
#   bash scripts/build_lambda.sh
set -euo pipefail

DIST="dist"
PKG="$DIST/lambda_package"
OUTPUT="$DIST/pipelineguard-lambda.zip"

echo "Cleaning previous build..."
rm -rf "$PKG" "$OUTPUT"
mkdir -p "$PKG"

echo "Installing dependencies into package directory..."
pip install -r requirements.txt --target "$PKG" --quiet --upgrade

echo "Copying pipelineguard source..."
cp -r pipelineguard "$PKG/"

echo "Zipping package..."
cd "$PKG"
zip -r "../../$OUTPUT" . -q
cd -

SIZE=$(du -sh "$OUTPUT" | cut -f1)
echo "Lambda package ready: $OUTPUT ($SIZE)"
echo ""
echo "Deploy with:"
echo "  aws lambda update-function-code --function-name <name> --zip-file fileb://$OUTPUT"
