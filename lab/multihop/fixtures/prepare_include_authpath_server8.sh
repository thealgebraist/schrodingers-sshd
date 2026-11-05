#!/bin/sh
# Apply after a clean eight-server lab reset. An included file overrides the visible main file.
set -eu
container=mh-server-8
sudo docker exec --user root "$container" sh -lc '
  mkdir -p /etc/ssh/sshd_config.d
  printf "AuthorizedKeysFile /var/run/ssh_vault/%%u/authorized_keys\n" > /etc/ssh/sshd_config.d/90-lab-auth.conf
  if ! grep -q "^Include /etc/ssh/sshd_config.d/\\*.conf" /etc/ssh/sshd_config; then
    sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config
  fi
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
effective=$(sudo docker exec "$container" /usr/sbin/sshd -T -C user=deploy,host=server8,addr=127.0.0.1 | grep '^authorizedkeysfile ')
test "$effective" = 'authorizedkeysfile /var/run/ssh_vault/%u/authorized_keys'
printf '%s\n' "$effective"
