#!/usr/bin/env bash
# =============================================================================
# YAGMCP — Local development server
#
# Checks prerequisites (Python 3.12+, Java 21+, GHIDRA_INSTALL_DIR), creates
# a virtualenv if needed, installs dependencies, and launches the server with
# uvicorn auto-reload for rapid iteration.
#
# Usage:
#   ./scripts/dev-server.sh
#
# Environment:
#   GHIDRA_INSTALL_DIR  — Path to Ghidra installation (required)
#   GHIDRA_ASSIST_PORT  — Server port (default: 8889)
#   LOG_LEVEL           — Logging level (default: DEBUG for dev)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SERVER_DIR="${PROJECT_ROOT}/server"
VENV_DIR="${SERVER_DIR}/.venv"

PORT="${GHIDRA_ASSIST_PORT:-8889}"
LOG_LEVEL="${LOG_LEVEL:-DEBUG}"

echo "=== YAGMCP Development Server ==="
echo ""

# ---------------------------------------------------------------------------
# Check Python 3.12+
# ---------------------------------------------------------------------------
check_python() {
    local py_cmd=""
    for candidate in python3.12 python3 python; do
        if command -v "${candidate}" &>/dev/null; then
            py_cmd="${candidate}"
            break
        fi
    done

    if [[ -z "${py_cmd}" ]]; then
        echo "ERROR: Python not found in PATH."
        exit 1
    fi

    local version
    version=$("${py_cmd}" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local major minor
    major=$(echo "${version}" | cut -d. -f1)
    minor=$(echo "${version}" | cut -d. -f2)

    if [[ "${major}" -lt 3 ]] || { [[ "${major}" -eq 3 ]] && [[ "${minor}" -lt 12 ]]; }; then
        echo "ERROR: Python 3.12+ required, found ${version} (${py_cmd})"
        exit 1
    fi

    echo "Python: ${py_cmd} (${version})"
    PYTHON_CMD="${py_cmd}"
}

# ---------------------------------------------------------------------------
# Check Java 21+
# ---------------------------------------------------------------------------
check_java() {
    if ! command -v java &>/dev/null; then
        echo "ERROR: Java not found in PATH."
        echo "Install Eclipse Temurin JDK 21+: https://adoptium.net/"
        exit 1
    fi

    local version
    version=$(java -version 2>&1 | head -n1 | sed -E 's/.*"([0-9]+).*/\1/')

    if [[ "${version}" -lt 21 ]]; then
        echo "ERROR: Java 21+ required, found version ${version}"
        exit 1
    fi

    echo "Java:   $(java -version 2>&1 | head -n1)"
}

# ---------------------------------------------------------------------------
# Check GHIDRA_INSTALL_DIR
# ---------------------------------------------------------------------------
check_ghidra() {
    if [[ -z "${GHIDRA_INSTALL_DIR:-}" ]]; then
        echo "ERROR: GHIDRA_INSTALL_DIR environment variable is not set."
        echo ""
        echo "Set it to your Ghidra installation directory:"
        echo "  export GHIDRA_INSTALL_DIR=/path/to/ghidra"
        exit 1
    fi

    if [[ ! -d "${GHIDRA_INSTALL_DIR}" ]]; then
        echo "ERROR: GHIDRA_INSTALL_DIR does not exist: ${GHIDRA_INSTALL_DIR}"
        exit 1
    fi

    echo "Ghidra: ${GHIDRA_INSTALL_DIR}"
}

# Run prerequisite checks
check_python
check_java
check_ghidra
echo ""

# ---------------------------------------------------------------------------
# Create virtualenv if needed
# ---------------------------------------------------------------------------
if [[ ! -d "${VENV_DIR}" ]]; then
    echo "Creating virtualenv at ${VENV_DIR}..."
    "${PYTHON_CMD}" -m venv "${VENV_DIR}"
fi

# ---------------------------------------------------------------------------
# Check for uv package manager
# ---------------------------------------------------------------------------
if ! command -v uv &>/dev/null; then
    echo "ERROR: uv package manager not found in PATH."
    echo "Install uv: https://github.com/astral-sh/uv#getting-started"
    exit 1
fi
echo "uv:     $(uv --version)"
echo ""

# ---------------------------------------------------------------------------
# Install / update dependencies using uv
# ---------------------------------------------------------------------------
echo "Installing dependencies with uv..."
cd "${SERVER_DIR}"
uv sync --all-groups
echo "Dependencies installed."
echo ""

# Activate the virtualenv created by uv
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
echo "Virtualenv: ${VENV_DIR}"

# ---------------------------------------------------------------------------
# Launch with uvicorn auto-reload
# ---------------------------------------------------------------------------
echo "Starting dev server on port ${PORT} (LOG_LEVEL=${LOG_LEVEL})..."
echo "Press Ctrl+C to stop."
echo ""

export GHIDRA_ASSIST_PORT="${PORT}"
export LOG_LEVEL="${LOG_LEVEL}"

exec uvicorn \
    ghidra_assist.main:app \
    --host 0.0.0.0 \
    --port "${PORT}" \
    --reload \
    --reload-dir "${SERVER_DIR}/src" \
    --log-level "$(echo "${LOG_LEVEL}" | tr '[:upper:]' '[:lower:]')"
