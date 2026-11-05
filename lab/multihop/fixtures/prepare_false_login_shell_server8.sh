#!/bin/sh
# Apply after a clean reset. Authentication works, but deploy's login shell
# immediately exits before it can run the requested remote command.
set -eu

sudo docker exec --user root mh-server-8 sh -lc '
  grep -q "^deploy:x:1000:1000::/home/deploy:/bin/bash$" /etc/passwd
  sed -i "s|^deploy:x:1000:1000::/home/deploy:/bin/bash$|deploy:x:1000:1000::/home/deploy:/bin/false|" /etc/passwd
  getent passwd deploy
'

printf '%s\n' '### triggering the SSH command'
set +e
sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/false-shell-stdout.log 2> /tmp/false-shell-stderr.log
status=$?
set -e
test "$status" -eq 1
test ! -s /tmp/false-shell-stdout.log
test ! -s /tmp/false-shell-stderr.log
printf 'preflight_exit=%s stdout_bytes=0 stderr_bytes=0\n' "$status"
printf '%s\n' '### confirming authentication reached the session'
sudo docker logs --tail 30 mh-server-8 2>&1 | grep -E 'Accepted publickey|Starting session: command|Close session' | tail -n 8
