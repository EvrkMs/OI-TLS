FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 iptables tcpdump ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/captures"]

ENTRYPOINT ["/entrypoint.sh"]
