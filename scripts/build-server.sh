#!/usr/bin/env bash
# =============================================================================
# YAGMCP — Build the Docker server image
#
# Builds the yagmcp-server Docker image from server/Dockerfile and reports
# the final image size.
#
# Usage:
#   ./scripts/build-server.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SERVER_DIR="${PROJECT_ROOT}/server"

IMAGE_NAME="yagmcp-server"
IMAGE_TAG="latest"
FULL_TAG="${IMAGE_NAME}:${IMAGE_TAG}"

echo "=== YAGMCP Server Docker Build ==="
echo "Context:  ${SERVER_DIR}"
echo "Image:    ${FULL_TAG}"
echo ""

# ---------------------------------------------------------------------------
# Check Docker is available
# ---------------------------------------------------------------------------
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found in PATH."
    exit 1
fi

# ---------------------------------------------------------------------------
# Build the image
# ---------------------------------------------------------------------------
echo "Building Docker image..."
echo ""

docker build \
    --tag "${FULL_TAG}" \
    --file "${SERVER_DIR}/Dockerfile" \
    "${SERVER_DIR}"

# ---------------------------------------------------------------------------
# Report result
# ---------------------------------------------------------------------------
echo ""
echo "=== Build Complete ==="

IMAGE_SIZE=$(docker image inspect "${FULL_TAG}" --format='{{.Size}}' 2>/dev/null || echo "0")
if [[ "${IMAGE_SIZE}" -gt 0 ]]; then
    # Convert bytes to human-readable
    IMAGE_SIZE_MB=$(( IMAGE_SIZE / 1024 / 1024 ))
    echo "Image: ${FULL_TAG}"
    echo "Size:  ${IMAGE_SIZE_MB} MB"
else
    echo "Image: ${FULL_TAG}"
    echo "Size:  (unable to determine)"
fi

echo ""
echo "Run with:"
echo "  cd ${PROJECT_ROOT}/deploy"
echo "  cp .env.template .env   # edit as needed"
echo "  docker compose up -d"
