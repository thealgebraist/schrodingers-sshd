#!/bin/sh
# Apply after a clean eight-server reset. The valid user certificate forces a
# command that prints server7 instead of running the requested hostname.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

sudo docker exec mh-client ssh-keygen -q -t ed25519 -N '' -f /tmp/mh-user-ca
sudo docker exec mh-client sh -c 'ssh-keygen -y -f /home/deploy/.ssh/id_ed25519 > /tmp/mh-user-key.pub'
sudo docker exec mh-client sh -lc 'ssh-keygen -q -s /tmp/mh-user-ca -I eac-force-command -n deploy -V -5m:+1h -O force-command="echo server7" /tmp/mh-user-key.pub'

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

printf '%s\n' '### user certificate'
sudo docker exec mh-client ssh-keygen -Lf /tmp/mh-user-key-cert.pub
printf '%s\n' '### actual server8 name resolution'
sudo docker exec mh-server-7 getent hosts server8
printf '%s\n' '### observed command result'
sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname
