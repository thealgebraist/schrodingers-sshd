#!/bin/sh
# Apply after a clean eight-server lab reset. Pin all jump keys correctly and pin a stale server8 key.
set -eu
python3 - <<'PY'
from pathlib import Path
p = Path("client/.ssh/config")
s = p.read_text()
assert s.count("StrictHostKeyChecking no") == 1
assert s.count("UserKnownHostsFile /dev/null") == 1
s = s.replace("StrictHostKeyChecking no", "StrictHostKeyChecking yes")
s = s.replace("UserKnownHostsFile /dev/null", "UserKnownHostsFile /home/deploy/.ssh/known_hosts")
p.write_text(s)
PY
known_hosts=client/.ssh/known_hosts
: > "$known_hosts"
for i in 1 2 3 4 5 6 7; do
  key=$(sudo docker exec "mh-server-$i" cat /etc/ssh/ssh_host_ed25519_key.pub)
  printf 'server%s %s\n' "$i" "$key" >> "$known_hosts"
done
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
ssh-keygen -q -t ed25519 -N '' -f "$tmpdir/stale_hostkey"
stale=$(cat "$tmpdir/stale_hostkey.pub")
printf 'server8 %s\n' "$stale" >> "$known_hosts"
chmod 0600 "$known_hosts"
effective=$(sudo docker exec mh-client ssh -G server8 | grep -E '^(stricthostkeychecking|userknownhostsfile) ')
printf '%s\n' "$effective"
