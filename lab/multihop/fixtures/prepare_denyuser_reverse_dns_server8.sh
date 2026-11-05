#!/bin/sh
# Apply after a clean eight-server lab reset.
set -eu

sudo docker exec --user root mh-server-8 sh -lc '
  mkdir -p /etc/ssh/sshd_config.d
  sed -i "1i UseDNS yes" /etc/ssh/sshd_config
  printf "DenyUsers deploy@mh-server-7.mh-7-8\\n" > /etc/ssh/sshd_config.d/90-lab-policy.conf
  if ! grep -q "^Include /etc/ssh/sshd_config.d/\\*.conf" /etc/ssh/sshd_config; then
    sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config
  fi
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'

sudo docker exec mh-server-8 sh -lc '
  printf "%s\\n" "### source reverse lookup"
  getent hosts 10.201.78.7
  printf "%s\\n" "### effective UseDNS"
  /usr/sbin/sshd -T | grep "^usedns "
  printf "%s\\n" "### effective DenyUsers"
  /usr/sbin/sshd -T | grep "^denyusers "
'

if sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/ssh-dns-deny-preflight 2>&1; then
  cat /tmp/ssh-dns-deny-preflight
  echo 'fixture invalid: connection unexpectedly succeeded' >&2
  exit 2
fi
cat /tmp/ssh-dns-deny-preflight
grep -q 'Permission denied (publickey)' /tmp/ssh-dns-deny-preflight
