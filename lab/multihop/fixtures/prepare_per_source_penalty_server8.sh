#!/bin/sh
# Apply after a clean reset. Two decoy agent identities hit MaxAuthTries; the
# resulting auth failure temporarily penalizes later connections from server7.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

python3 - "$ROOT/client/.ssh/config" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
marker = "Host server8\n"
if text.count(marker) != 1:
    raise SystemExit(f"expected one exact server8 stanza, found {text.count(marker)}")
extra = (
    "    IdentityFile /tmp/mh-decoy1\n"
    "    IdentityFile /tmp/mh-decoy2\n"
    "    IdentityAgent /tmp/mh-agent.sock\n"
    "    IdentitiesOnly no\n"
)
path.write_text(text.replace(marker, marker + extra, 1), encoding="utf-8")
PY

sudo docker exec --user 1000:1000 mh-client sh -lc '
  ssh-keygen -q -t ed25519 -N "" -f /tmp/mh-decoy1
  ssh-keygen -q -t ed25519 -N "" -f /tmp/mh-decoy2
  eval "$(ssh-agent -a /tmp/mh-agent.sock)"
  SSH_AUTH_SOCK=/tmp/mh-agent.sock ssh-add /tmp/mh-decoy1 /tmp/mh-decoy2 /home/deploy/.ssh/id_ed25519
'
sudo docker exec --user root mh-server-8 sh -lc '
  printf "\nMaxAuthTries 2\nPerSourcePenalties authfail:20s\n" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'

printf '%s\n' '### effective admission settings'
sudo docker exec mh-server-8 /usr/sbin/sshd -T | grep -E '^(maxauthtries|persourcepenalties) '
printf '%s\n' '### triggering authentication failure'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/per-source-penalty-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: too-many-authentication-failures was not triggered' >&2
  exit 2
fi
grep -q 'Too many authentication failures' /tmp/per-source-penalty-preflight.log
if ! sudo docker logs --tail 20 mh-server-8 2>&1 | grep -q 'srclimit_penalise:.*active penalty'; then
  printf '%s\n' 'fixture invalid: sshd did not create the expected source penalty' >&2
  exit 2
fi
printf '%s\n' 'sshd created the expected temporary source penalty.'
tail -n 8 /tmp/per-source-penalty-preflight.log
