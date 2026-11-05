#!/bin/sh
# Apply after a clean eight-server lab reset. Creates a valid user certificate
# whose principal is rejected by server8's authorized-CA principals policy.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

sudo docker exec mh-client ssh-keygen -q -t ed25519 -N '' -f /tmp/mh-user-ca
sudo docker exec mh-client sh -c 'ssh-keygen -y -f /home/deploy/.ssh/id_ed25519 > /tmp/mh-user-key.pub'
sudo docker exec mh-client ssh-keygen -q -s /tmp/mh-user-ca -I eac-user-cert -n wrongprincipal -V -5m:+1h /tmp/mh-user-key.pub

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

printf '%s\n' '### certificate'
sudo docker exec mh-client ssh-keygen -Lf /tmp/mh-user-key-cert.pub
printf '%s\n' '### server8 authorized CA'
sudo docker exec mh-server-8 cat /home/deploy/.ssh/authorized_keys
printf '%s\n' '### observed connection'
set +e
sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/user-cert-client.log 2>&1
ssh_status=$?
set -e
tail -n 18 /tmp/user-cert-client.log
test "$ssh_status" -ne 0
grep -q 'Permission denied (publickey)' /tmp/user-cert-client.log
printf 'ssh_exit_code=%s\n' "$ssh_status"
printf '%s\n' '### server8 authentication log'
sudo docker logs --tail 35 mh-server-8 2>&1 | tail -n 20
