#!/bin/sh
# Apply after a clean eight-server lab reset. The restriction matches only connections from server7.
set -eu
sudo docker exec --user root mh-server-8 sh -lc '
  mkdir -p /etc/ssh/sshd_config.d
  printf "Match Address 10.201.78.7\\n    PubkeyAuthentication no\\n" > /etc/ssh/sshd_config.d/90-lab-match.conf
  if ! grep -q "^Include /etc/ssh/sshd_config.d/\\*.conf" /etc/ssh/sshd_config; then
    printf "\\nInclude /etc/ssh/sshd_config.d/*.conf\\n" >> /etc/ssh/sshd_config
  fi
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
effective=$(sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep '^pubkeyauthentication ')
generic=$(sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=127.0.0.1 | grep '^pubkeyauthentication ')
printf 'matched source: %s\ngeneric source: %s\n' "$effective" "$generic"
test "$effective" = 'pubkeyauthentication no'
test "$generic" = 'pubkeyauthentication yes'
if sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/dbc-match-address-observed 2>&1; then
  cat /tmp/dbc-match-address-observed
  echo 'fixture invalid: connection unexpectedly succeeded' >&2
  exit 2
fi
cat /tmp/dbc-match-address-observed
grep -Fq 'Permission denied ()' /tmp/dbc-match-address-observed
