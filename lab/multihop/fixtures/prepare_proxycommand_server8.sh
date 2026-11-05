#!/bin/sh
# Apply after a clean eight-server lab reset. The valid ProxyJump remains configured but is bypassed by ProxyCommand.
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
sudo docker exec mh-client ssh -G server8 | grep -E '^(proxyjump|proxycommand) '
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/dbc-proxycommand-observed 2>&1; then
  cat /tmp/dbc-proxycommand-observed
  echo 'fixture invalid: connection unexpectedly succeeded' >&2
  exit 2
fi
cat /tmp/dbc-proxycommand-observed
grep -q 'kex_exchange_identification: Connection closed by remote host' /tmp/dbc-proxycommand-observed
