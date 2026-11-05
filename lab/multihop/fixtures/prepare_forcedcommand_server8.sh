#!/bin/sh
# Apply after a clean eight-server lab reset. The target key forces a failing command.
set -eu
container=mh-server-8
path=/home/deploy/.ssh/authorized_keys
sudo docker exec --user root "$container" sh -lc "sed -i 's/^ssh-ed25519/command=\"\/bin\/false\" ssh-ed25519/' '$path'"
entry=$(sudo docker exec "$container" head -n 1 "$path")
case "$entry" in
  'command="/bin/false" ssh-ed25519 '*) ;;
  *) echo 'Expected the client key with a forced command' >&2; exit 1 ;;
esac
printf '%s\n' "$entry"
