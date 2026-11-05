#!/bin/sh
# Apply after a clean eight-server lab reset. Server8 requires two distinct
# public-key authentication steps, but this client has only one configured key.
set -eu

printf '\nAuthenticationMethods publickey,publickey\n' | sudo docker exec -i --user root mh-server-8 sh -c 'cat >> /etc/ssh/sshd_config'
sudo docker exec mh-server-8 /usr/sbin/sshd -t -f /etc/ssh/sshd_config
sudo docker exec --user root mh-server-8 kill -HUP 1

printf '%s\n' '### effective authentication policy for the real upstream address'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep -E '^(authenticationmethods|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|usepam) '
printf '%s\n' '### observed connection'
set +e
sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/authentication-methods-client.log 2>&1
ssh_status=$?
set -e
grep -E 'partial success|Authenticated using|Permission denied' /tmp/authentication-methods-client.log | tail -n 8
test "$ssh_status" -ne 0
grep -q 'Permission denied (publickey)' /tmp/authentication-methods-client.log
printf 'ssh_exit_code=%s\n' "$ssh_status"
printf '%s\n' '### server8 authentication log'
sudo docker logs --tail 35 mh-server-8 2>&1 | tail -n 18
