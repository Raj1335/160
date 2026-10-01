FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl grep iperf3 iproute2 iputils-ping procps python3 \
    strongswan strongswan-starter tcpdump \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
