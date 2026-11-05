#!/bin/sh
# Apply after a clean eight-server reset. A single OUTPUT rule drops SSH from
# the final jump host to server8; sshd on both hosts remains correctly configured.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

sudo docker build -f "$ROOT/fixtures/netfilter.Dockerfile" -t ssh-lab-netfilter:local "$ROOT"
sudo docker run --rm --network container:mh-server-7 --cap-add NET_ADMIN \
  ssh-lab-netfilter:local -I OUTPUT 1 -d 10.201.78.8 -p tcp --dport 22 -j DROP

printf '%s\n' '### filter rule present'
sudo docker run --rm --network container:mh-server-7 --cap-add NET_ADMIN \
  ssh-lab-netfilter:local -C OUTPUT -d 10.201.78.8 -p tcp --dport 22 -j DROP
sudo docker run --rm --network container:mh-server-7 --cap-add NET_ADMIN \
  ssh-lab-netfilter:local -S OUTPUT
printf '%s\n' '### healthy SSH to jump host'
sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server7 hostname
printf '%s\n' '### failed SSH to target'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/egress-firewall-preflight.log 2>&1; then
  cat /tmp/egress-firewall-preflight.log
  printf '%s\n' 'fixture invalid: target connection unexpectedly succeeded' >&2
  exit 2
fi
grep -E 'Connecting to|Connection timed out|stdio forwarding failed|Connection closed by UNKNOWN' /tmp/egress-firewall-preflight.log | tail -n 10
