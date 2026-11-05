#!/bin/sh
# Apply after a clean eight-server lab reset. Preserve key bytes while making its mode unsafe.
set -eu
path=client/.ssh/id_ed25519
before=$(sha256sum "$path")
chmod 0666 "$path"
after=$(sha256sum "$path")
mode=$(stat -c '%a' "$path")
test "$before" = "$after"
test "$mode" = 666
printf '%s\n' "$mode $(stat -c '%U:%G' "$path") $path" "$after"
