#!/bin/sh
# Apply after a clean reset. Four independent faults become visible in sequence.
set -eu
python3 - <<'PY'
from pathlib import Path
p = Path("client/.ssh/config")
s = p.read_text()
marker = "Host server8\n"
assert s.count(marker) == 1
settings = (
    "Host server8\n"
    "    ProxyCommand /bin/false\n"
    "    IdentityFile /tmp/mh-decoy1\n"
    "    IdentityFile /tmp/mh-decoy2\n"
    "    IdentityAgent /tmp/mh-agent.sock\n"
    "    IdentitiesOnly no\n"
)
s = s.replace(marker, settings, 1)
p.write_text(s)
PY
sudo docker exec --user root mh-server-7 sh -lc "printf '10.201.78.7 server8\\n' >> /etc/hosts"
sudo docker exec --user root mh-server-8 sh -lc '
  mkdir -p /etc/ssh/sshd_config.d
  printf "DenyUsers deploy@10.201.78.7\\n" > /etc/ssh/sshd_config.d/90-lab-policy.conf
  if ! grep -q "^Include /etc/ssh/sshd_config.d/\\*.conf" /etc/ssh/sshd_config; then
    printf "\\nInclude /etc/ssh/sshd_config.d/*.conf\\n" >> /etc/ssh/sshd_config
  fi
  sed -i "1i MaxAuthTries 2" /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
sudo docker exec --user 1000:1000 mh-client sh -lc '
  ssh-keygen -q -t ed25519 -N "" -f /tmp/mh-decoy1
  ssh-keygen -q -t ed25519 -N "" -f /tmp/mh-decoy2
  eval "$(ssh-agent -a /tmp/mh-agent.sock)"
  SSH_AUTH_SOCK=/tmp/mh-agent.sock ssh-add /tmp/mh-decoy1 /tmp/mh-decoy2 /home/deploy/.ssh/id_ed25519
'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/dbc-staged4-observed 2>&1; then
  cat /tmp/dbc-staged4-observed
  echo 'fixture invalid: first-stage connection unexpectedly succeeded' >&2
  exit 2
fi
grep -q 'kex_exchange_identification: Connection closed by remote host' /tmp/dbc-staged4-observed
cat /tmp/dbc-staged4-observed
