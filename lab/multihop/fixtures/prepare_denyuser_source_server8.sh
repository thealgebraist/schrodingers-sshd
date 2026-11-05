#!/bin/sh
# Apply after a clean eight-server lab reset. The allowed source pattern omits the real server7 address.
set -eu
sudo docker exec --user root mh-server-8 sh -lc '
  mkdir -p /etc/ssh/sshd_config.d
  printf "DenyUsers deploy@10.201.78.7\\n" > /etc/ssh/sshd_config.d/90-lab-policy.conf
  if ! grep -q "^Include /etc/ssh/sshd_config.d/\\*.conf" /etc/ssh/sshd_config; then
    sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config
  fi
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep '^denyusers '
if sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/dbc-allowuser-observed 2>&1; then
  cat /tmp/dbc-allowuser-observed
  echo 'fixture invalid: connection unexpectedly succeeded' >&2
  exit 2
fi
cat /tmp/dbc-allowuser-observed
grep -q 'Permission denied (publickey)' /tmp/dbc-allowuser-observed
