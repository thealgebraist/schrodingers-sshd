#!/bin/sh
# Apply after a clean eight-server lab reset. Restricts forwarding for the lab key only.
set -eu
container=mh-server-5
path=/home/deploy/.ssh/authorized_keys
before=$(sudo docker exec "$container" sha256sum "$path")
sudo docker exec --user root "$container" sh -lc "sed -i 's/^ssh-ed25519/no-port-forwarding ssh-ed25519/' '$path'"
after=$(sudo docker exec "$container" sha256sum "$path")
entry=$(sudo docker exec "$container" sh -lc "head -n 1 '$path'")
effective=$(sudo docker exec "$container" /usr/sbin/sshd -T | grep '^allowtcpforwarding ')
test "$before" != "$after"
case "$entry" in
  'no-port-forwarding ssh-ed25519 '*) ;;
  *) echo 'Expected a valid no-port-forwarding authorized_keys entry' >&2; exit 1 ;;
esac
test "$effective" = 'allowtcpforwarding yes'
printf '%s\n' "$entry" "$effective"
