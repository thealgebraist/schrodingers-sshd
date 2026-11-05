#!/bin/sh
# Apply after a clean eight-server lab reset. The certificate is valid for
# deploy but is restricted to the client's direct-lab address, not the address
# that server8 sees through ProxyJump.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

sudo docker exec mh-client ssh-keygen -q -t ed25519 -N '' -f /tmp/mh-user-ca
sudo docker exec mh-client sh -c 'ssh-keygen -y -f /home/deploy/.ssh/id_ed25519 > /tmp/mh-user-key.pub'
sudo docker exec mh-client ssh-keygen -q -s /tmp/mh-user-ca -I eac-source-address -n deploy \
  -V -5m:+1h -O source-address=10.201.1.2 /tmp/mh-user-key.pub

ca_entry=$(sudo docker exec mh-client cat /tmp/mh-user-ca.pub | awk '{print "cert-authority,principals=\"deploy\" " $1 " " $2}')
printf '%s\n' "$ca_entry" | sudo docker exec -i --user root mh-server-8 sh -c 'cat > /home/deploy/.ssh/authorized_keys'
sudo docker exec --user root mh-server-8 chown deploy:deploy /home/deploy/.ssh/authorized_keys
sudo docker exec --user root mh-server-8 chmod 0600 /home/deploy/.ssh/authorized_keys

python3 - "$ROOT/client/.ssh/config" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
marker = "Host server8\n"
if text.count(marker) != 1:
    raise SystemExit(f"expected one exact server8 stanza, found {text.count(marker)}")
start = text.index(marker) + len(marker)
text = text[:start] + "    CertificateFile /tmp/mh-user-key-cert.pub\n" + text[start:]
path.write_text(text, encoding="utf-8")
PY

if sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/user-cert-source-client.log 2>&1; then
  cat /tmp/user-cert-source-client.log
  printf '%s\n' 'fixture invalid: certificate unexpectedly authenticated' >&2
  exit 2
fi
grep -q 'Permission denied (publickey)' /tmp/user-cert-source-client.log
printf '%s\n' '### certificate source address'
sudo docker exec mh-client ssh-keygen -Lf /tmp/mh-user-key-cert.pub | grep -E 'Valid:|Principals:|deploy|Critical Options:|source-address'
printf '%s\n' '### observed client error'
cat /tmp/user-cert-source-client.log
printf '%s\n' '### server8 authentication log'
sudo docker logs --tail 40 mh-server-8 2>&1 | grep -E 'Connection from|Certificate|source-address|Failed publickey|userauth-request' | tail -n 14
