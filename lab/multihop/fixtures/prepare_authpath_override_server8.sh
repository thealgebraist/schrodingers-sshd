#!/bin/sh
# Apply after a clean eight-server lab reset. A visible home key is an inactive decoy.
set -eu
container=mh-server-8
sudo docker exec --user root "$container" sh -lc '
  sed -i "s|^AuthorizedKeysFile .*|AuthorizedKeysFile /var/run/ssh_vault/%u/authorized_keys|" /etc/ssh/sshd_config
  chmod 0666 /home/deploy/.ssh/authorized_keys
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
effective=$(sudo docker exec "$container" /usr/sbin/sshd -T | grep '^authorizedkeysfile ')
metadata=$(sudo docker exec "$container" stat -c '%a %U:%G %n' /home/deploy/.ssh/authorized_keys)
test "$effective" = 'authorizedkeysfile /var/run/ssh_vault/%u/authorized_keys'
test "$(printf '%s' "$metadata" | cut -d' ' -f1)" = 666
printf '%s\n' "$effective" "$metadata"
