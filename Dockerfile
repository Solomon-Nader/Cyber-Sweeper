# CyberSweep - reproducible runtime image
#
# Build:  docker build -t cybersweep .
# Run:    docker run --rm --network host -v cybersweep-data:/data cybersweep scan 192.168.1.0/24 -p common
#
# --network host is needed so the container sees the real LAN (Linux only; on
# Docker Desktop for Windows/macOS the container can only reach the VM network).
# The CLI is the entrypoint; the Tkinter GUI is intended to run natively.

FROM python:3.12-slim

LABEL org.opencontainers.image.title="CyberSweep" \
      org.opencontainers.image.description="Python network inspector: discovery, port scan, service ID, CVE lookup" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CYBERSWEEP_HOME=/data

# nmap for the accurate engine, iputils-ping for ICMP discovery, tk for optional GUI use
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY cybersweep ./cybersweep
RUN pip install --no-cache-dir .

VOLUME ["/data"]
ENTRYPOINT ["cybersweep", "--no-banner"]
CMD ["--help"]
