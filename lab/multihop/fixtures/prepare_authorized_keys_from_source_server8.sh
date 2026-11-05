#!/bin/sh
# Apply after a clean reset. The authorized key allows the direct client IP,
# but server8 sees the final ProxyJump host as its TCP source.
set -eu

sudo docker exec --user root mh-server-8 sh -lc '
  file=/home/deploy/.ssh/authorized_keys
  test "$(wc -l < "$file")" -eq 1
  ! grep -q "^from=" "$file"
  prefix="from=\"10.201.1.2\" "
  sed -i "1s|^|$prefix|" "$file"
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
'

printf '%s\n' '### target authorized key restriction'
sudo docker exec mh-server-8 cat /home/deploy/.ssh/authorized_keys | cut -d' ' -f1
printf '%s\n' '### triggering the SSH failure'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/authorized-keys-from-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: source-restricted key unexpectedly authenticated' >&2
  exit 2
fi
grep -q 'Permission denied (publickey)' /tmp/authorized-keys-from-preflight.log
printf '%s\n' '### observed client error'
tail -n 8 /tmp/authorized-keys-from-preflight.log
printf '%s\n' '### server8 authentication evidence'
sudo docker logs --tail 50 mh-server-8 2>&1 | grep -E 'Connection from|not from a permitted|not permitted|Failed publickey|userauth-request' | tail -n 12
