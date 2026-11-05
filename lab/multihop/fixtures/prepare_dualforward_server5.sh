#!/bin/sh
# Apply after a clean eight-server lab reset. Key restriction and PermitOpen both deny the next hop.
set -eu
container=mh-server-5
sudo docker exec --user root "$container" sh -lc '
  sed -i "s/^ssh-ed25519/restrict ssh-ed25519/" /home/deploy/.ssh/authorized_keys
  printf "\nPermitOpen server2:22\n" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
key=$(sudo docker exec "$container" head -n 1 /home/deploy/.ssh/authorized_keys)
tcp=$(sudo docker exec "$container" /usr/sbin/sshd -T | grep '^allowtcpforwarding ')
allowed=$(sudo docker exec "$container" /usr/sbin/sshd -T | grep '^permitopen ')
case "$key" in 'restrict ssh-ed25519 '*) ;; *) exit 1 ;; esac
test "$tcp" = 'allowtcpforwarding yes'
test "$allowed" = 'permitopen server2:22'
printf '%s\n' "$key" "$tcp" "$allowed"
