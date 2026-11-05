#!/bin/sh
# Apply after a clean eight-server lab reset. Server5 is an intermediate jump.
set -eu
sudo docker exec --user root mh-server-5 sh -lc '
  printf "\\nAllowTcpForwarding no\\n" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t
  kill -HUP 1
'
effective=$(sudo docker exec mh-server-5 /usr/sbin/sshd -T | grep '^allowtcpforwarding ')
test "$effective" = 'allowtcpforwarding no'
printf '%s\n' "$effective"
