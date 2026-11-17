# Defender agent (component B): Claude Agent SDK runtime as a persistent process.
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash agent

COPY defender/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --default-timeout 180 --retries 10 -r /tmp/requirements.txt
COPY contracts /tmp/contracts
RUN pip install --no-cache-dir /tmp/contracts && rm -rf /tmp/contracts

COPY defender/defender /opt/defender/defender
COPY defender/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
ENV PYTHONPATH=/opt/defender PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
