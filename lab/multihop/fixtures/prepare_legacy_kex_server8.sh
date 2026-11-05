#!/bin/sh
# Apply after a clean eight-server lab reset. Force an obsolete KEX suite on the target.
set -eu
container=mh-server-8
sudo docker exec --user root "$container" sh -lc '
  printf "\nKexAlgorithms diffie-hellman-group1-sha1\n" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
effective=$(sudo docker exec "$container" /usr/sbin/sshd -T | grep '^kexalgorithms ')
test "$effective" = 'kexalgorithms diffie-hellman-group1-sha1'
printf '%s\n' "$effective"
