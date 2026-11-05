FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --uid 1000 --create-home --shell /bin/bash deploy && echo 'deploy:labpass123' | chpasswd && mkdir -p /run/sshd /home/deploy/.ssh && chown -R deploy:deploy /home/deploy/.ssh && chmod 700 /home/deploy/.ssh
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
