FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["iptables"]
