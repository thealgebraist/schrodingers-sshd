#!/bin/sh
# Apply after a clean eight-server lab reset. Restrict the final jump to server2:22.
set -eu
container=mh-server-7
sudo docker exec --user root "$container" sh -lc 'printf "\nPermitOpen server2:22\n" >> /etc/ssh/sshd_config; /usr/sbin/sshd -t -f /etc/ssh/sshd_config; kill -HUP 1'
tcp=$(sudo docker exec "$container" /usr/sbin/sshd -T | grep '^allowtcpforwarding ')
allowed=$(sudo docker exec "$container" /usr/sbin/sshd -T | grep '^permitopen ')
test "$tcp" = 'allowtcpforwarding yes'
test "$allowed" = 'permitopen server2:22'
printf '%s\n' "$tcp" "$allowed"
