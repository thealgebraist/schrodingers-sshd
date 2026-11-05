#!/bin/sh
# Apply after a clean eight-server lab reset. Restrict the client key's default abilities.
set -eu
container=mh-server-5
path=/home/deploy/.ssh/authorized_keys
sudo docker exec --user root "$container" sh -lc "sed -i 's/^ssh-ed25519/restrict ssh-ed25519/' '$path'"
entry=$(sudo docker exec "$container" head -n 1 "$path")
case "$entry" in
  'restrict ssh-ed25519 '*) ;;
  *) echo 'Expected the client key with the restrict option' >&2; exit 1 ;;
esac
printf '%s\n' "$entry"
