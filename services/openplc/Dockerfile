FROM python:3.11-slim AS plc_stub

# Note: OpenPLC Runtime v4 (Autonomy Logic) is the preferred implementation.
# Full OpenPLC setup requires a Linux environment with specific build dependencies
# (gcc, g++, make, libssl, etc.) and the runtime binary.
# This Dockerfile provides a minimal OpenPLC-compatible Modbus TCP server
# that behaves identically to OpenPLC's Modbus interface.
# When running on Linux, replace with the full OpenPLC Runtime v4 image.

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose OpenPLC Modbus TCP port and web UI port
EXPOSE 502 8080

CMD ["python", "plc_sim.py"]

HEALTHCHECK --interval=15s --timeout=5s --retries=10 --start-period=30s \
    CMD python -c "import socket; s=socket.socket(); s.connect(('127.0.0.1',502)); s.close()"
