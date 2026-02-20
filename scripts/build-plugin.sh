#!/usr/bin/env bash
# =============================================================================
# YAGMCP — Build the GhidraAssist Ghidra plugin
#
# Runs gradle buildExtension in the plugin/ directory, producing a ZIP that
# can be installed into Ghidra via File > Install Extensions.
#
# Usage:
#   ./scripts/build-plugin.sh [/path/to/ghidra]
#
# If no argument is given, GHIDRA_INSTALL_DIR environment variable is used.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLUGIN_DIR="${PROJECT_ROOT}/plugin"

# ---------------------------------------------------------------------------
# Resolve Ghidra install directory
# ---------------------------------------------------------------------------
GHIDRA_DIR="${1:-${GHIDRA_INSTALL_DIR:-}}"

if [[ -z "${GHIDRA_DIR}" ]]; then
    echo "ERROR: Ghidra installation directory not specified."
    echo ""
    echo "Usage: $0 [/path/to/ghidra]"
    echo "   or: GHIDRA_INSTALL_DIR=/path/to/ghidra $0"
    exit 1
fi

if [[ ! -d "${GHIDRA_DIR}" ]]; then
    echo "ERROR: Directory does not exist: ${GHIDRA_DIR}"
    exit 1
fi

if [[ ! -f "${GHIDRA_DIR}/support/buildExtension.gradle" ]]; then
    echo "ERROR: Not a valid Ghidra installation (missing support/buildExtension.gradle): ${GHIDRA_DIR}"
    exit 1
fi

echo "=== YAGMCP Plugin Build ==="
echo "Ghidra installation: ${GHIDRA_DIR}"
echo "Plugin source:       ${PLUGIN_DIR}"
echo ""

# ---------------------------------------------------------------------------
# Check for Gradle
# ---------------------------------------------------------------------------
if command -v gradle &>/dev/null; then
    GRADLE_CMD="gradle"
elif [[ -f "${PLUGIN_DIR}/gradlew" ]]; then
    GRADLE_CMD="${PLUGIN_DIR}/gradlew"
else
    echo "ERROR: gradle not found in PATH and no gradlew wrapper present."
    echo "Install Gradle (https://gradle.org/install/) or add a Gradle wrapper."
    exit 1
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
echo "Building with: ${GRADLE_CMD}"
echo ""

cd "${PLUGIN_DIR}"
${GRADLE_CMD} -PGHIDRA_INSTALL_DIR="${GHIDRA_DIR}" buildExtension

# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------
echo ""
echo "=== Build Complete ==="

DIST_DIR="${PLUGIN_DIR}/dist"
if [[ -d "${DIST_DIR}" ]]; then
    ZIP_FILE=$(ls -t "${DIST_DIR}"/*.zip 2>/dev/null | head -n1)
    if [[ -n "${ZIP_FILE}" ]]; then
        echo "Plugin ZIP: ${ZIP_FILE}"
        echo "Size:       $(du -h "${ZIP_FILE}" | cut -f1)"
        echo ""
        echo "Install with: ./scripts/install-plugin.sh ${GHIDRA_DIR}"
    else
        echo "WARNING: No ZIP found in ${DIST_DIR}"
    fi
else
    echo "WARNING: dist/ directory not found — check build output above."
fi
