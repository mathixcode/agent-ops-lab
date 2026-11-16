# Egress gateway (component D).
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        nftables iproute2 chrony util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin mitm

COPY contracts /tmp/contracts
RUN pip install --no-cache-dir mitmproxy==12.3.1 /tmp/contracts && rm -rf /tmp/contracts

COPY gateway/ /opt/gateway/
ENTRYPOINT ["bash", "/opt/gateway/entrypoint.sh"]
