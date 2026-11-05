#!/bin/sh
# Apply after a clean eight-server lab reset. Two independent forwarding gates fail at different hops.
set -eu
sudo docker exec --user root mh-server-5 sh -lc '
  printf "\\nAllowTcpForwarding no\\n" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t
  kill -HUP 1
'
sudo docker exec --user root mh-server-7 sed -i 's/^ssh-ed25519 /no-port-forwarding ssh-ed25519 /' /home/deploy/.ssh/authorized_keys
sudo docker exec mh-server-5 /usr/sbin/sshd -T | grep '^allowtcpforwarding '
sudo docker exec mh-server-7 cat /home/deploy/.ssh/authorized_keys | cut -d' ' -f1
if sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/dbc-crosshop-observed 2>&1; then
  cat /tmp/dbc-crosshop-observed
  echo 'fixture invalid: connection unexpectedly succeeded' >&2
  exit 2
fi
cat /tmp/dbc-crosshop-observed
