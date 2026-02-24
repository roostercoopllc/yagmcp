#!/usr/bin/env bash
# =============================================================================
# YAGMCP — Test connectivity to a running server
#
# Runs a series of HTTP checks against the YAGMCP server and reports
# pass/fail for each endpoint.
#
# Usage:
#   ./scripts/test-connection.sh [server-url]
#
# Default server URL: http://localhost:8889
# =============================================================================
set -euo pipefail

SERVER_URL="${1:-http://localhost:8889}"
# Strip trailing slash
SERVER_URL="${SERVER_URL%/}"

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
test_endpoint() {
    local name="$1"
    local url="$2"
    local method="${3:-GET}"
    local data="${4:-}"
    local expected_status="${5:-200}"

    printf "%-40s " "${name}..."

    local http_code
    local response

    if [[ -n "${data}" ]]; then
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -X "${method}" \
            -H "Content-Type: application/json" \
            -d "${data}" \
            --connect-timeout 5 \
            --max-time 30 \
            "${url}" 2>/dev/null) || response="000"
    else
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -X "${method}" \
            --connect-timeout 5 \
            --max-time 10 \
            "${url}" 2>/dev/null) || response="000"
    fi

    if [[ "${response}" == "${expected_status}" ]]; then
        echo "PASS (HTTP ${response})"
        PASS=$((PASS + 1))
    else
        echo "FAIL (HTTP ${response}, expected ${expected_status})"
        FAIL=$((FAIL + 1))
    fi
}

test_json_field() {
    local name="$1"
    local url="$2"
    local jq_filter="$3"
    local expected="$4"

    printf "%-40s " "${name}..."

    local body
    body=$(curl -s --connect-timeout 5 --max-time 10 "${url}" 2>/dev/null) || body=""

    if [[ -z "${body}" ]]; then
        echo "FAIL (no response)"
        FAIL=$((FAIL + 1))
        return
    fi

    # Use python as a portable jq alternative
    local value
    value=$(echo "${body}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    keys = '${jq_filter}'.strip('.').split('.')
    for k in keys:
        d = d[k]
    print(d)
except Exception as e:
    print(f'ERROR: {e}')
" 2>/dev/null) || value="ERROR"

    if [[ "${value}" == "${expected}" ]]; then
        echo "PASS (${value})"
        PASS=$((PASS + 1))
    else
        echo "FAIL (got '${value}', expected '${expected}')"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Check that curl is available
# ---------------------------------------------------------------------------
if ! command -v curl &>/dev/null; then
    echo "ERROR: curl is required but not found in PATH."
    exit 1
fi

echo "=== YAGMCP Connection Test ==="
echo "Server: ${SERVER_URL}"
echo ""

# ---------------------------------------------------------------------------
# Test 1: Health endpoint
# ---------------------------------------------------------------------------
test_endpoint "Health endpoint" "${SERVER_URL}/api/health"
test_json_field "Health status field" "${SERVER_URL}/api/health" ".status" "ok"

# ---------------------------------------------------------------------------
# Test 2: List repositories (projects)
# ---------------------------------------------------------------------------
test_endpoint "List projects" "${SERVER_URL}/api/projects"

# ---------------------------------------------------------------------------
# Test 3: Sample chat request
# ---------------------------------------------------------------------------
CHAT_PAYLOAD='{"message":"What is a function prologue in assembly?","repository":"","program":""}'
test_endpoint "Chat endpoint" "${SERVER_URL}/api/chat" "POST" "${CHAT_PAYLOAD}"

# ---------------------------------------------------------------------------
# Test 4: OpenAPI spec
# ---------------------------------------------------------------------------
test_endpoint "OpenAPI spec" "${SERVER_URL}/openapi.json"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results ==="
TOTAL=$((PASS + FAIL))
echo "Passed: ${PASS}/${TOTAL}"
echo "Failed: ${FAIL}/${TOTAL}"

if [[ "${FAIL}" -gt 0 ]]; then
    echo ""
    echo "Some tests failed. Check that:"
    echo "  - YAGMCP server is running at ${SERVER_URL}"
    echo "  - Ollama is accessible from the server"
    echo "  - Firewall rules allow the connection"
    exit 1
fi

echo ""
echo "All tests passed."
