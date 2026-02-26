# =============================================================================
# YAGMCP Server — Multi-stage Docker Build
# Headless Ghidra + Python MCP server for LLM-assisted reverse engineering
# =============================================================================

# ---------------------------------------------------------------------------
# Build arguments
# ---------------------------------------------------------------------------
ARG PYTHON_VERSION=3.12
ARG GHIDRA_VERSION=12.0.3
ARG GHIDRA_DATE=20260210
ARG JAVA_VERSION=21

# ============================= BUILDER STAGE ================================
FROM python:${PYTHON_VERSION}-slim AS builder

ARG GHIDRA_VERSION
ARG GHIDRA_DATE
ARG JAVA_VERSION

# Install build-time dependencies: JDK 21 (Eclipse Temurin) + utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
        unzip \
        ca-certificates \
        gnupg \
    && mkdir -p /etc/apt/keyrings \
    && wget -qO- https://packages.adoptium.net/artifactory/api/gpg/key/public \
       | gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb $(. /etc/os-release && echo $VERSION_CODENAME) main" \
       > /etc/apt/sources.list.d/adoptium.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends temurin-${JAVA_VERSION}-jdk \
    && rm -rf /var/lib/apt/lists/*

# Download and extract Ghidra from official NSA GitHub releases
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
RUN wget -q -O /tmp/ghidra.zip \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_INSTALL_DIR} \
    && rm /tmp/ghidra.zip

# Install uv for faster, more reliable dependency management
RUN pip install --no-cache-dir uv

# Copy application source and install Python dependencies using uv
WORKDIR /build
COPY pyproject.toml .
COPY uv.lock .
COPY src/ src/

# Install dependencies using uv (faster, deterministic, uses locked versions from uv.lock)
# --compile-bytecode speeds up runtime startup
RUN uv pip install --no-cache-dir --compile-bytecode --system .

# ============================= RUNTIME STAGE ================================
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG JAVA_VERSION

LABEL maintainer="roostercoopllc"
LABEL description="YAGMCP — Headless Ghidra MCP server"

# Install runtime dependencies: JDK 21 (headless) + curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
        ca-certificates \
        gnupg \
        curl \
    && mkdir -p /etc/apt/keyrings \
    && wget -qO- https://packages.adoptium.net/artifactory/api/gpg/key/public \
       | gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb $(. /etc/os-release && echo $VERSION_CODENAME) main" \
       > /etc/apt/sources.list.d/adoptium.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends temurin-${JAVA_VERSION}-jre \
    && apt-get purge -y wget gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy Ghidra installation from builder
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
COPY --from=builder ${GHIDRA_INSTALL_DIR} ${GHIDRA_INSTALL_DIR}

# Copy installed Python packages and scripts from builder
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin /usr/local/bin

# Create non-root user
RUN groupadd --gid 1000 ghidra \
    && useradd --uid 1000 --gid ghidra --shell /bin/bash --create-home ghidra

# Create required directories
RUN mkdir -p /repos /data \
    && chown -R ghidra:ghidra /repos /data /home/ghidra

# Set environment
ENV PYTHONUNBUFFERED=1
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/temurin-${JAVA_VERSION}-jre
ENV PATH="${JAVA_HOME}/bin:${PATH}"

WORKDIR /home/ghidra
USER ghidra

EXPOSE 8889

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=90s \
    CMD curl -f http://localhost:8889/api/health || exit 1

CMD ["python", "-m", "ghidra_assist.main"]
