#!/bin/sh
# Apply after a clean reset. Server8 accepts only legacy ssh-rsa user-auth
# signatures while the client has an RSA key and uses modern RSA/SHA-2.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

sudo docker exec --user 1000:1000 mh-client ssh-keygen -q -t rsa -b 3072 -N '' -f /tmp/mh-userauth-rsa
public_key=$(sudo docker exec mh-client cat /tmp/mh-userauth-rsa.pub)
printf '%s\n' "$public_key" | sudo docker exec -i --user root mh-server-8 sh -c 'cat > /home/deploy/.ssh/authorized_keys'
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
text = text.replace(marker, marker + "    IdentityFile /tmp/mh-userauth-rsa\n", 1)
path.write_text(text, encoding="utf-8")
PY

sudo docker exec --user root mh-server-8 sh -lc '
  printf "%s\\n" "PubkeyAcceptedAlgorithms ssh-rsa" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'

printf '%s\n' '### effective server user-auth signature policy'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep '^pubkeyacceptedalgorithms '
printf '%s\n' '### client effective user-auth configuration'
sudo docker exec mh-client ssh -G server8 | grep -E '^(identityfile|pubkeyacceptedalgorithms) '
printf '%s\n' '### triggering the SSH failure'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/pubkey-signature-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: user authentication unexpectedly succeeded' >&2
  exit 2
fi
grep -q 'Permission denied (publickey)' /tmp/pubkey-signature-preflight.log
grep -E 'no mutual signature algorithm|Offering public key|signing using|Permission denied' /tmp/pubkey-signature-preflight.log | tail -n 12
printf '%s\n' '### server8 authentication log'
sudo docker logs --tail 40 mh-server-8 2>&1 | grep -E 'Connection from|Failed publickey|Accepted publickey|signature algorithm' | tail -n 12
