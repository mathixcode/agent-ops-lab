# Hypervisor host for the target VM (component A). The target itself is the QEMU guest;
# this container only plays the role a KVM host or cloud hypervisor plays.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-system-x86 qemu-utils genisoimage \
        ipxe-qemu python3 iproute2 nftables openssh-client curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

COPY target/hypervisor/ /opt/hv/
COPY target/provision/ /opt/target/provision/
COPY target/versions.env /opt/target/versions.env
RUN chmod 0755 /opt/hv/entrypoint.sh

VOLUME /images
ENTRYPOINT ["/opt/hv/entrypoint.sh"]
CMD ["run"]
