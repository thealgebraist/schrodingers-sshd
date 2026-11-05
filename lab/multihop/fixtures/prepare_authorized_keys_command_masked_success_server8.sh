#!/bin/sh
# Apply after a clean reset. Both lookup candidates return the client's key;
# candidate A adds a forced command that prints the expected hostname.
set -eu

cat > /tmp/mh-lookup-a <<'EOF'
#!/bin/sh
[ "$1" = deploy ] || exit 0
cat /etc/ssh/lookup-a.pub
EOF
cat > /tmp/mh-lookup-b <<'EOF'
#!/bin/sh
[ "$1" = deploy ] || exit 0
cat /etc/ssh/lookup-b.pub
EOF
sudo docker cp /tmp/mh-lookup-a mh-server-8:/usr/local/bin/lookup-a >/dev/null
sudo docker cp /tmp/mh-lookup-b mh-server-8:/usr/local/bin/lookup-b >/dev/null
sudo docker exec --user root mh-server-8 sh -lc '
  cp /lab/authorized_keys /etc/ssh/lookup-b.pub
  chown root:root /usr/local/bin/lookup-a /usr/local/bin/lookup-b /etc/ssh/lookup-b.pub
  chmod 0755 /usr/local/bin/lookup-a /usr/local/bin/lookup-b
  chmod 0644 /etc/ssh/lookup-b.pub
  sed -i "s|^AuthorizedKeysFile .ssh/authorized_keys$|AuthorizedKeysFile none|" /etc/ssh/sshd_config
  printf "%s\\n" "AuthorizedKeysCommand /usr/local/bin/lookup-a %u" "AuthorizedKeysCommandUser nobody" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'

key_line=$(sudo docker exec mh-server-8 cat /etc/ssh/lookup-b.pub)
printf 'command="echo server8" %s\n' "$key_line" > /tmp/mh-lookup-a.pub
sudo docker cp /tmp/mh-lookup-a.pub mh-server-8:/etc/ssh/lookup-a.pub >/dev/null
sudo docker exec --user root mh-server-8 chown root:root /etc/ssh/lookup-a.pub
sudo docker exec --user root mh-server-8 chmod 0644 /etc/ssh/lookup-a.pub

printf '%s\n' '### effective lookup settings'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep -E '^authorizedkeys(command|commanduser|file) '
printf '%s\n' '### lookup outputs as the configured command user'
sudo docker exec --user nobody mh-server-8 /usr/local/bin/lookup-a deploy
sudo docker exec --user nobody mh-server-8 /usr/local/bin/lookup-b deploy
printf '%s\n' '### verifying the apparently successful command'
output=$(sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname)
test "$output" = server8
printf 'preflight_exit=0 output=%s\n' "$output"
printf '%s\n' '### server8 authentication and session log'
sudo docker logs --tail 40 mh-server-8 2>&1 | grep -E 'Connection from|Accepted publickey|Starting session|Close session' | tail -n 10
