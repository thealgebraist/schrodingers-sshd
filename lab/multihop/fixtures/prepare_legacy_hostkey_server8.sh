#!/bin/sh
# Apply after a clean eight-server lab reset. Offer only the deprecated ssh-rsa signature.
set -eu
container=mh-server-8
sudo docker exec --user root "$container" sh -lc '
  printf "\nHostKeyAlgorithms ssh-rsa\n" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
effective=$(sudo docker exec "$container" /usr/sbin/sshd -T | grep '^hostkeyalgorithms ')
test "$effective" = 'hostkeyalgorithms ssh-rsa'
printf '%s\n' "$effective"
