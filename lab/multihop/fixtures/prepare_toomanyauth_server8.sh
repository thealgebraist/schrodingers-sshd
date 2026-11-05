#!/bin/sh
# Apply after a clean eight-server lab reset. The generated decoy private keys stay inside mh-client.
set -eu
python3 - <<'PY'
from pathlib import Path
p = Path("client/.ssh/config")
s = p.read_text()
assert s.count("Host *\n") == 1
assert s.count("    IdentitiesOnly yes\n") == 1
s = s.replace("    IdentitiesOnly yes\n", "    IdentitiesOnly no\n", 1)
s = "Host server8\n    IdentityFile /tmp/mh-decoy1\n    IdentityFile /tmp/mh-decoy2\n    IdentityAgent /tmp/mh-agent.sock\n    IdentitiesOnly no\n\n" + s
p.write_text(s)
PY
sudo docker exec mh-server-8 sh -lc "printf '\\nMaxAuthTries 2\\n' >> /etc/ssh/sshd_config && /usr/sbin/sshd -t && kill -HUP 1"
sudo docker exec mh-client sh -lc '
  ssh-keygen -q -t ed25519 -N "" -f /tmp/mh-decoy1
  ssh-keygen -q -t ed25519 -N "" -f /tmp/mh-decoy2
  eval "$(ssh-agent -a /tmp/mh-agent.sock)"
  SSH_AUTH_SOCK=/tmp/mh-agent.sock ssh-add /tmp/mh-decoy1 /tmp/mh-decoy2 /home/deploy/.ssh/id_ed25519
'
sudo docker exec mh-client sh -lc 'SSH_AUTH_SOCK=/tmp/mh-agent.sock ssh-add -l'
sudo docker exec mh-server-8 /usr/sbin/sshd -T | grep '^maxauthtries '
if sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/dbc-toomanyauth-observed 2>&1; then
  cat /tmp/dbc-toomanyauth-observed
  echo 'fixture invalid: authentication unexpectedly succeeded' >&2
  exit 2
fi
cat /tmp/dbc-toomanyauth-observed
grep -q 'Too many authentication failures' /tmp/dbc-toomanyauth-observed
