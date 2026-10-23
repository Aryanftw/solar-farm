FROM zeek/zeek:6.0.3

USER root

# Install Python for the forwarder script and curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip tcpreplay curl \
    && rm -rf /var/lib/apt/lists/*

# Install CISA ICSNPP-Modbus package
RUN zkg install icsnpp-modbus --force || true

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["/bin/sh", "-c", "/app/entrypoint.sh"]
