#!/bin/sh
# Apply after a clean reset. The default sshd remains on loopback; a second
# daemon serves the network interface using a separate config with key auth off.
set -eu

sudo docker exec --user root mh-server-8 sh -lc '
  sed -i "s/^ListenAddress 0\\.0\\.0\\.0$/ListenAddress 127.0.0.1/" /etc/ssh/sshd_config
  mkdir -p /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/90-lab-active.conf <<"EOF"
Port 22
ListenAddress 10.201.78.8
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/sshd-alt.pid
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
UsePAM no
AllowUsers deploy
StrictModes yes
LogLevel VERBOSE
EOF
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config.d/90-lab-active.conf
  kill -HUP 1
'

sudo docker exec -d --user root mh-server-8 /usr/sbin/sshd -D -E /var/log/sshd-alt.log -f /etc/ssh/sshd_config.d/90-lab-active.conf

attempt=0
while [ "$attempt" -lt 10 ]; do
  if sudo docker exec mh-server-8 sh -lc 'p=$(cat /run/sshd-alt.pid 2>/dev/null || true); [ -n "$p" ] && kill -0 "$p" 2>/dev/null'; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
sudo docker exec mh-server-8 sh -lc 'p=$(cat /run/sshd-alt.pid 2>/dev/null || true); [ -n "$p" ] && kill -0 "$p" 2>/dev/null'
sudo docker exec mh-server-8 grep -q 'Server listening on 10.201.78.8 port 22' /var/log/sshd-alt.log

printf '%s\n' '### default sshd config effective values'
sudo docker exec mh-server-8 /usr/sbin/sshd -T | grep -E '^(listenaddress|pubkeyauthentication) '
printf '%s\n' '### alternate sshd config effective values'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -f /etc/ssh/sshd_config.d/90-lab-active.conf | grep -E '^(listenaddress|pubkeyauthentication) '
printf '%s\n' '### running sshd commands'
sudo docker exec mh-server-8 sh -lc 'for p in /proc/[0-9]*; do [ -r "$p/cmdline" ] || continue; c=$(tr "\\000" " " < "$p/cmdline" 2>/dev/null || true); case "$c" in *sshd*) printf "pid=%s command=%s\\n" "${p##*/}" "$c";; esac; done'

printf '%s\n' '### SSH command through the network listener'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/alternate-sshd-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: public-key authentication unexpectedly succeeded' >&2
  exit 2
fi
grep -Fq 'Permission denied ()' /tmp/alternate-sshd-preflight.log
grep -E 'Permission denied|Server host key|Authentications that can continue' /tmp/alternate-sshd-preflight.log | tail -n 10
sudo docker exec mh-server-8 tail -n 20 /var/log/sshd-alt.log
sleep 2
sudo docker exec --user root mh-server-8 truncate -s 0 /var/log/sshd-alt.log
