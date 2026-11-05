#!/bin/sh
# Apply after a clean eight-server lab reset. A large but valid user
# certificate triggers loss of oversized IP packets on the server7-to-server8
# link; small SSH probes and the ordinary multi-hop route still work.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

sudo docker build -f "$ROOT/fixtures/netfilter.Dockerfile" -t ssh-lab-netfilter:local "$ROOT"

sudo docker exec mh-client ssh-keygen -q -t ed25519 -N '' -f /tmp/mh-user-ca
sudo docker exec mh-client sh -c 'ssh-keygen -y -f /home/deploy/.ssh/id_ed25519 > /tmp/mh-user-key.pub'
principals=deploy
i=0
while [ "$i" -lt 200 ]; do
  principals="$principals,p$i"
  i=$((i + 1))
done
sudo docker exec mh-client ssh-keygen -q -s /tmp/mh-user-ca -I pmtu-test -n "$principals" -V -5m:+1h /tmp/mh-user-key.pub

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
directives = (
    "    CertificateFile /tmp/mh-user-key-cert.pub\n"
    "    KexAlgorithms curve25519-sha256\n"
    "    ServerAliveInterval 2\n"
    "    ServerAliveCountMax 2\n"
)
text = text[:start] + directives + text[start:]
path.write_text(text, encoding="utf-8")
PY

# The filter runs in server7's network namespace and drops only large IP
# packets addressed to server8's SSH daemon. TCP setup and small SSH packets
# remain passable. Resetting the lab removes the temporary namespace/rule.
sudo docker run --rm --network container:mh-server-7 --cap-add NET_ADMIN \
  ssh-lab-netfilter:local -I OUTPUT 1 -d 10.201.78.8 -p tcp --dport 22 \
  -m length --length 1400:65535 -j DROP

printf '%s\n' '### large client certificate'
sudo docker exec mh-client wc -c /tmp/mh-user-key-cert.pub
sudo docker exec mh-client ssh-keygen -Lf /tmp/mh-user-key-cert.pub | sed -n '1,12p'
printf '%s\n' '### ordinary SSH path to server7'
sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server7 hostname
printf '%s\n' '### small-certificate control over the same link'
sudo docker exec mh-client rm -f /tmp/mh-user-key-cert.pub
sudo docker exec mh-client ssh-keygen -q -s /tmp/mh-user-ca -I pmtu-small -n deploy -V -5m:+1h /tmp/mh-user-key.pub
sudo docker exec mh-client wc -c /tmp/mh-user-key-cert.pub
sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname
sudo docker exec mh-client rm -f /tmp/mh-user-key-cert.pub
sudo docker exec mh-client ssh-keygen -q -s /tmp/mh-user-ca -I pmtu-test -n "$principals" -V -5m:+1h /tmp/mh-user-key.pub
printf '%s\n' '### target SSH attempt (limited to 15 seconds)'
set +e
sudo docker exec mh-client timeout -s TERM 15 ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/payload-size-client.log 2>&1
ssh_status=$?
set -e
grep -E 'Connection to UNKNOWN|Timeout|timed out' /tmp/payload-size-client.log | tail -n 5
tail -n 18 /tmp/payload-size-client.log
test "$ssh_status" -ne 0
printf 'ssh_exit_code=%s\n' "$ssh_status"
printf '%s\n' '### server8 authentication log'
sudo docker logs --tail 35 mh-server-8 2>&1 | tail -n 20
server_log_path=$(sudo docker inspect --format '{{.LogPath}}' mh-server-8)
sudo truncate -s 0 "$server_log_path"
sleep 2
test -z "$(sudo docker logs mh-server-8 2>&1)"
printf '%s\n' 'server8 setup logs cleared; transient source penalty expired'
