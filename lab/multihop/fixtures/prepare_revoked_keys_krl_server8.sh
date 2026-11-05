#!/bin/sh
# Apply after a clean eight-server lab reset. The active KRL mistakenly
# revokes the currently authorized client key; the baseline KRL revokes only
# an unrelated decoy key and still keeps revocation checking enabled.
set -eu

sudo docker exec --user root mh-server-8 ssh-keygen -q -t ed25519 -N '' -f /tmp/revoked-decoy
sudo docker exec --user root mh-server-8 ssh-keygen -q -k -f /etc/ssh/revoked-baseline.krl /tmp/revoked-decoy.pub
sudo docker exec --user root mh-server-8 ssh-keygen -q -k -f /etc/ssh/revoked.krl /lab/authorized_keys
sudo docker exec --user root mh-server-8 chmod 0644 /etc/ssh/revoked.krl /etc/ssh/revoked-baseline.krl
printf '\nRevokedKeys /etc/ssh/revoked.krl\n' | sudo docker exec -i --user root mh-server-8 sh -c 'cat >> /etc/ssh/sshd_config'
sudo docker exec mh-server-8 /usr/sbin/sshd -t -f /etc/ssh/sshd_config
sudo docker exec --user root mh-server-8 kill -HUP 1

printf '%s\n' '### effective policy and KRL queries'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep '^revokedkeys '
for file in revoked.krl revoked-baseline.krl; do
  printf '### %s\n' "$file"
  set +e
  sudo docker exec mh-server-8 ssh-keygen -Q -f "/etc/ssh/$file" /lab/authorized_keys
  query_status=$?
  set -e
  printf 'query_exit_code=%s\n' "$query_status"
done

printf '%s\n' '### observed connection'
set +e
sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/revoked-keys-client.log 2>&1
ssh_status=$?
set -e
grep -E 'revoked|Permission denied' /tmp/revoked-keys-client.log | tail -n 8
test "$ssh_status" -ne 0
grep -q 'Permission denied (publickey)' /tmp/revoked-keys-client.log
printf 'ssh_exit_code=%s\n' "$ssh_status"
printf '%s\n' '### server8 authentication log'
sudo docker logs --tail 35 mh-server-8 2>&1 | tail -n 20
