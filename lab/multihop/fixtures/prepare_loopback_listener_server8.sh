#!/bin/sh
# Apply after a clean eight-server lab reset. sshd remains active, but only
# accepts connections on server8's loopback address.
set -eu

sudo docker exec --user root mh-server-8 sed -i \
  's/^ListenAddress 0\.0\.0\.0$/ListenAddress 127.0.0.1/' \
  /etc/ssh/sshd_config
sudo docker exec mh-server-8 /usr/sbin/sshd -t
sudo docker exec --user root mh-server-8 kill -HUP 1

printf '%s\n' '### effective sshd listener'
sudo docker exec mh-server-8 /usr/sbin/sshd -T | grep '^listenaddress '
printf '%s\n' '### client command'
if output=$(sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname 2>&1); then
  printf 'unexpected_success=%s\n' "$output" >&2
  exit 2
else
  status=$?
  printf 'preflight_exit=%s output=%s\n' "$status" "$output"
fi
