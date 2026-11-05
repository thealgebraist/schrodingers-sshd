#!/bin/sh
# Apply after a clean reset. First prepare and preflight the size-sensitive
# certificate path, then add an independent source-scoped account denial.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

"$ROOT/fixtures/prepare_payload_size_blackhole_server8.sh"

sudo docker exec --user root mh-server-8 sh -lc '
  mkdir -p /etc/ssh/sshd_config.d
  printf "DenyUsers deploy@10.201.78.7\\n" > /etc/ssh/sshd_config.d/90-lab-policy.conf
  if ! grep -Fqx "Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config; then
    sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config
  fi
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep '^denyusers '

printf '%s\n' '### compact certificate reveals the independent account-policy gate'
sudo docker exec mh-client rm -f /tmp/mh-user-key-cert.pub
sudo docker exec mh-client ssh-keygen -q -s /tmp/mh-user-ca -I pmtu-small -n deploy -V -5m:+1h /tmp/mh-user-key.pub
set +e
sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/payload-size-denyuser-small.log 2>&1
small_status=$?
set -e
cat /tmp/payload-size-denyuser-small.log
test "$small_status" -ne 0
grep -q 'Permission denied (publickey)' /tmp/payload-size-denyuser-small.log

printf '%s\n' '### restore the large certificate that triggers the initial timeout'
principals=deploy
i=0
while [ "$i" -lt 200 ]; do
  principals="$principals,p$i"
  i=$((i + 1))
done
sudo docker exec mh-client rm -f /tmp/mh-user-key-cert.pub
sudo docker exec mh-client ssh-keygen -q -s /tmp/mh-user-ca -I pmtu-test -n "$principals" -V -5m:+1h /tmp/mh-user-key.pub
sudo docker exec mh-client wc -c /tmp/mh-user-key-cert.pub

# Remove preflight log evidence and let transient source-rate penalties expire.
server_log_path=$(sudo docker inspect --format '{{.LogPath}}' mh-server-8)
sudo truncate -s 0 "$server_log_path"
sleep 2
test -z "$(sudo docker logs mh-server-8 2>&1)"
printf '%s\n' 'server8 setup logs cleared; transient source penalty expired'
