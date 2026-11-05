#!/bin/sh
# Apply after a clean reset. Three faults appear successively as earlier SSH stages are repaired.
set -eu
python3 - <<'PY'
from pathlib import Path
p = Path("client/.ssh/config")
s = p.read_text()
marker = "Host server8\n"
assert s.count(marker) == 1
s = s.replace(marker, marker + "    ProxyCommand /bin/false\n", 1)
p.write_text(s)
PY
sudo docker exec --user root mh-server-7 sh -lc "printf '10.201.78.7 server8\\n' >> /etc/hosts"
sudo docker exec --user root mh-server-8 sh -lc '
  mkdir -p /etc/ssh/sshd_config.d
  printf "DenyUsers deploy@10.201.78.7\\n" > /etc/ssh/sshd_config.d/90-lab-policy.conf
  if ! grep -q "^Include /etc/ssh/sshd_config.d/\\*.conf" /etc/ssh/sshd_config; then
    printf "\\nInclude /etc/ssh/sshd_config.d/*.conf\\n" >> /etc/ssh/sshd_config
  fi
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/dbc-staged-observed 2>&1; then
  cat /tmp/dbc-staged-observed
  echo 'fixture invalid: first-stage connection unexpectedly succeeded' >&2
  exit 2
fi
cat /tmp/dbc-staged-observed
grep -q 'kex_exchange_identification: Connection closed by remote host' /tmp/dbc-staged-observed
