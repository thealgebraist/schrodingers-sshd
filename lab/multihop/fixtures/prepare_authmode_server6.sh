#!/bin/sh
# Apply after a clean eight-server lab reset. Preserves authorized_keys bytes and owner.
set -eu
container=mh-server-6
path=/home/deploy/.ssh/authorized_keys
before=$(sudo docker exec "$container" sha256sum "$path")
sudo docker exec --user root "$container" chmod 0666 "$path"
after=$(sudo docker exec "$container" sha256sum "$path")
metadata=$(sudo docker exec "$container" stat -c '%a %U:%G %n' "$path")
test "$before" = "$after"
test "$(printf '%s' "$metadata" | cut -d' ' -f1)" = 666
printf '%s\n' "$metadata" "$after"
