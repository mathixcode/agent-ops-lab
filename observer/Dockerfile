# Observer harness (component C): orchestrator, load generator, prober, datastore, scoring.
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        nftables iproute2 util-linux git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash observer

COPY contracts /tmp/contracts
COPY observer/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt /tmp/contracts && rm -rf /tmp/contracts

COPY observer/observer /opt/observer/observer
COPY observer/entrypoint.sh observer/lab-observer /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/lab-observer
ENV PYTHONPATH=/opt/observer PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
