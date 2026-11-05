#!/bin/sh
# Apply after a clean eight-server reset. Server8 incorrectly reuses server7's
# host-key lookup alias, so strict checking compares two different server keys.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
config="$ROOT/client/.ssh/config"
known_hosts="$ROOT/client/.ssh/known_hosts"

: > "$known_hosts"
sudo docker exec --user root mh-server-8 sh -lc '
  ssh-keygen -q -t ed25519 -N "" -f /tmp/mh-server8-hostkey
  install -o root -g root -m 0600 /tmp/mh-server8-hostkey /etc/ssh/ssh_host_ed25519_key
  install -o root -g root -m 0644 /tmp/mh-server8-hostkey.pub /etc/ssh/ssh_host_ed25519_key.pub
  kill -HUP 1
'
for server in 1 2 3 4 5 6 7 8; do
  key=$(sudo docker exec "mh-server-$server" cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1 " " $2}')
  printf 'server%s %s\n' "$server" "$key" >> "$known_hosts"
done
chmod 0600 "$known_hosts"

python3 - "$config" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = (
    "Host server8\n"
    "    HostKeyAlias server7\n"
    "    StrictHostKeyChecking yes\n"
    "    UserKnownHostsFile /home/deploy/.ssh/known_hosts\n\n"
    "Host *\n"
    "    StrictHostKeyChecking yes\n"
    "    UserKnownHostsFile /home/deploy/.ssh/known_hosts\n\n"
    + text
)
path.write_text(text, encoding="utf-8")
PY

effective=$(sudo docker exec mh-client ssh -G server8 | grep '^hostkeyalias ')
test "$effective" = 'hostkeyalias server7'
printf '%s\n' '### effective host identity' "$effective"
printf '%s\n' '### stored host keys'
ssh-keygen -lf "$known_hosts"
printf '%s\n' '### proxy host pin'
sudo docker exec mh-client ssh -G server7 | grep -E '^(hostkeyalias|stricthostkeychecking|userknownhostsfile) '
printf '%s\n' '### observed connection'
if sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/hostkeyalias-collision.log 2>&1; then
  cat /tmp/hostkeyalias-collision.log
  printf '%s\n' 'fixture invalid: connection unexpectedly succeeded' >&2
  exit 2
fi
grep -q 'REMOTE HOST IDENTIFICATION HAS CHANGED' /tmp/hostkeyalias-collision.log
cat /tmp/hostkeyalias-collision.log
