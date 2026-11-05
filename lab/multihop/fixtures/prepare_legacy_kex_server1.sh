#!/bin/sh
# Apply after a clean eight-server reset. Server1 is the first SSH jump.
set -eu
container=mh-server-1
sudo docker exec --user root "$container" sh -lc '
  printf "\nKexAlgorithms diffie-hellman-group1-sha1\n" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
effective=$(sudo docker exec "$container" /usr/sbin/sshd -T | grep '^kexalgorithms ')
test "$effective" = 'kexalgorithms diffie-hellman-group1-sha1'
printf '%s\n' '### server1 effective KEX' "$effective"
printf '%s\n' '### observed connection'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/legacy-kex-server1.log 2>&1; then
  cat /tmp/legacy-kex-server1.log
  printf '%s\n' 'fixture invalid: connection unexpectedly succeeded' >&2
  exit 2
fi
grep -q 'no matching key exchange method found' /tmp/legacy-kex-server1.log
grep -E 'Connecting to|Unable to negotiate|no matching key exchange method' /tmp/legacy-kex-server1.log | tail -n 8
