#!/bin/sh
# Apply after a clean reset. sshd uses one AuthorizedKeysCommand while the
# ordinary authorized_keys file is intentionally disabled.
set -eu

cat > /tmp/mh-lookup-b <<'EOF'
#!/bin/sh
[ "$1" = deploy ] || exit 0
cat /etc/ssh/lookup-b.pub
EOF
cat > /tmp/mh-lookup-a <<'EOF'
#!/bin/sh
[ "$1" = deploy ] || exit 0
cat /etc/ssh/lookup-a.pub
EOF
sudo docker cp /tmp/mh-lookup-b mh-server-8:/usr/local/bin/lookup-b >/dev/null
sudo docker cp /tmp/mh-lookup-a mh-server-8:/usr/local/bin/lookup-a >/dev/null

sudo docker exec --user root mh-server-8 sh -lc '
  cp /lab/authorized_keys /etc/ssh/lookup-b.pub
  cp /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/lookup-a.pub
  chown root:root /etc/ssh/lookup-b.pub /etc/ssh/lookup-a.pub /usr/local/bin/lookup-b /usr/local/bin/lookup-a
  chmod 0644 /etc/ssh/lookup-b.pub /etc/ssh/lookup-a.pub
  chmod 0755 /usr/local/bin/lookup-b /usr/local/bin/lookup-a
  sed -i "s|^AuthorizedKeysFile .ssh/authorized_keys$|AuthorizedKeysFile none|" /etc/ssh/sshd_config
  printf "%s\\n" "AuthorizedKeysCommand /usr/local/bin/lookup-a %u" "AuthorizedKeysCommandUser nobody" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'

printf '%s\n' '### effective key lookup configuration'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep -E '^authorizedkeys(command|commanduser|file) '
printf '%s\n' '### candidate fingerprints returned as nobody'
for name in a b; do
  sudo docker exec --user nobody mh-server-8 "/usr/local/bin/lookup-$name" deploy | ssh-keygen -lf -
done
printf '%s\n' '### triggering the SSH failure'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/authorized-keys-command-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: candidate A unexpectedly authenticated' >&2
  exit 2
fi
grep -q 'Permission denied (publickey)' /tmp/authorized-keys-command-preflight.log
tail -n 8 /tmp/authorized-keys-command-preflight.log
printf '%s\n' '### server8 authentication log'
sudo docker logs --tail 40 mh-server-8 2>&1 | grep -E 'Connection from|Failed publickey|Accepted publickey' | tail -n 8
