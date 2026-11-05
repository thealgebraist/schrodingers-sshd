#!/bin/sh
# Apply after a clean eight-server lab reset. An earlier exact Host stanza wins.
set -eu
config=client/.ssh/config
tmp=$(mktemp)
{
  printf 'Host server8\n    ProxyJump server6\n\n'
  cat "$config"
} > "$tmp"
cat "$tmp" > "$config"
rm -f "$tmp"
effective=$(sudo docker exec mh-client ssh -G server8 | grep '^proxyjump ')
test "$effective" = 'proxyjump server6'
printf '%s\n' "$effective"
