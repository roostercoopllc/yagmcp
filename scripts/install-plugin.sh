#!/usr/bin/env bash
# =============================================================================
# YAGMCP — Install the GhidraAssist plugin into Ghidra
#
# Finds the most recently built plugin ZIP from plugin/dist/ and copies it
# to the appropriate Ghidra extensions directory.
#
# Usage:
#   ./scripts/install-plugin.sh [/path/to/ghidra]
#
# If no argument is given, GHIDRA_INSTALL_DIR environment variable is used.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLUGIN_DIR="${PROJECT_ROOT}/plugin"
DIST_DIR="${PLUGIN_DIR}/dist"

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

# ---------------------------------------------------------------------------
# Find the built plugin ZIP
# ---------------------------------------------------------------------------
if [[ ! -d "${DIST_DIR}" ]]; then
    echo "ERROR: No dist/ directory found. Build the plugin first:"
    echo "  ./scripts/build-plugin.sh ${GHIDRA_DIR}"
    exit 1
fi

ZIP_FILE=$(ls -t "${DIST_DIR}"/*.zip 2>/dev/null | head -n1)
if [[ -z "${ZIP_FILE}" ]]; then
    echo "ERROR: No plugin ZIP found in ${DIST_DIR}. Build the plugin first:"
    echo "  ./scripts/build-plugin.sh ${GHIDRA_DIR}"
    exit 1
fi

echo "=== YAGMCP Plugin Install ==="
echo "Plugin ZIP: ${ZIP_FILE}"
echo ""

# ---------------------------------------------------------------------------
# Detect OS and determine extensions directory
# ---------------------------------------------------------------------------
detect_extensions_dir() {
    local ghidra_dir="$1"

    # Check if running on Windows (Git Bash / MSYS / WSL with Windows Ghidra)
    if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "$(uname -s)" == CYGWIN* ]]; then
        # Windows: Ghidra uses %USERPROFILE%/.ghidra/<version>/Extensions
        local ghidra_version
        ghidra_version=$(basename "${ghidra_dir}" | sed 's/ghidra_//' | sed 's/_PUBLIC.*//')
        local ext_dir="${USERPROFILE}/.ghidra/.ghidra_${ghidra_version}_PUBLIC/Extensions"
        echo "${ext_dir}"
        return
    fi

    # Check if WSL2 with a Windows Ghidra path (e.g., /mnt/c/...)
    if [[ "${ghidra_dir}" == /mnt/[a-z]/* ]]; then
        # WSL2 accessing Windows filesystem — extract the Windows user profile
        local win_drive="${ghidra_dir:5:1}"
        local ghidra_version
        ghidra_version=$(basename "${ghidra_dir}" | sed 's/ghidra_//' | sed 's/_PUBLIC.*//')
        # Try common Windows user profile locations
        local win_user_dir="/mnt/${win_drive}/Users"
        if [[ -d "${win_user_dir}" ]]; then
            local username
            username=$(ls "${win_user_dir}" | grep -v -E "^(Public|Default|All Users|desktop.ini)" | head -n1)
            if [[ -n "${username}" ]]; then
                local ext_dir="${win_user_dir}/${username}/.ghidra/.ghidra_${ghidra_version}_PUBLIC/Extensions"
                echo "${ext_dir}"
                return
            fi
        fi
    fi

    # Linux/macOS: use Ghidra's own Extensions directory
    echo "${ghidra_dir}/Ghidra/Extensions"
}

EXT_DIR=$(detect_extensions_dir "${GHIDRA_DIR}")

echo "Target OS:            $(uname -s)"
echo "Extensions directory: ${EXT_DIR}"
echo ""

# ---------------------------------------------------------------------------
# Create extensions directory if needed and copy the ZIP
# ---------------------------------------------------------------------------
mkdir -p "${EXT_DIR}"

DEST="${EXT_DIR}/$(basename "${ZIP_FILE}")"
cp "${ZIP_FILE}" "${DEST}"

echo "Installed: ${DEST}"
echo ""

# ---------------------------------------------------------------------------
# Post-install instructions
# ---------------------------------------------------------------------------
echo "=== Post-Install Steps ==="
echo ""
echo "1. Open Ghidra"
echo "2. Go to: File > Install Extensions..."
echo "3. Enable 'GhidraAssist' in the list (it should already appear)"
echo "4. Restart Ghidra"
echo ""
echo "If the extension does not appear automatically:"
echo "  - Ensure the ZIP is in: ${EXT_DIR}"
echo "  - Check Ghidra version compatibility"
echo "  - Review Ghidra's application.log for errors"
