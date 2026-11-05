#!/bin/sh
# Apply after a clean reset. A held, unauthenticated TCP connection occupies
# server8's MaxStartups=1:100:1 admission slot and deterministically drops SSH.
set -eu

sudo docker exec --user root mh-server-8 sh -lc '
  printf "\\nMaxStartups 1:100:1\\n" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'

printf '%s\n' '### effective admission threshold'
sudo docker exec mh-server-8 /usr/sbin/sshd -T | grep '^maxstartups '
printf '%s\n' '### hold one unauthenticated connection from the final jump host'
sudo docker exec -d mh-server-7 bash -lc 'exec 3<>/dev/tcp/server8/22; sleep 600'

attempt=0
while [ "$attempt" -lt 10 ]; do
  if sudo docker logs --tail 20 mh-server-8 2>&1 | grep -q 'Connection from 10.201.78.7'; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
sudo docker logs --tail 20 mh-server-8 2>&1 | grep -q 'Connection from 10.201.78.7'

printf '%s\n' '### connection failure under saturation'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/maxstartups-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: SSH unexpectedly succeeded' >&2
  exit 2
fi
grep -E 'kex_exchange_identification|Connection closed by remote host|Connection reset by peer|Connection closed by UNKNOWN port' /tmp/maxstartups-preflight.log | tail -n 8
sudo docker logs --tail 30 mh-server-8 2>&1 | grep -E 'MaxStartups|Connection from|drop connection' | tail -n 12
