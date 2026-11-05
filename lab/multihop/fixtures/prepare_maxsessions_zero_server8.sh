#!/bin/sh
# Apply after a clean reset. Public-key authentication and jump forwarding
# remain enabled, but server8 rejects shell, login, and subsystem sessions.
set -eu

sudo docker exec --user root mh-server-8 sh -lc '
  printf "\\nMaxSessions 0\\n" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'

printf '%s\n' '### effective target session limit'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep '^maxsessions '
printf '%s\n' '### forwarding remains enabled on the final jump host'
sudo docker exec mh-server-7 /usr/sbin/sshd -T -C user=deploy,host=server7,addr=10.201.78.7 | grep '^allowtcpforwarding '

if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/maxsessions-zero-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: session unexpectedly succeeded' >&2
  exit 2
fi
grep -Fq 'channel 0: open failed' /tmp/maxsessions-zero-preflight.log
sudo docker logs --tail 30 mh-server-8 2>&1 | grep -Fq 'no more sessions'
printf '%s\n' '### session-channel refusal'
grep -E 'Authenticated to server8|channel 0: open failed|Permission denied|stdio-forward' /tmp/maxsessions-zero-preflight.log | tail -n 12
printf '%s\n' '### server8 log'
sudo docker logs --tail 30 mh-server-8 2>&1 | tail -n 20
