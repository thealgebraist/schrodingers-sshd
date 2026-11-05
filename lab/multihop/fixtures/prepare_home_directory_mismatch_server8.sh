#!/bin/sh
# Apply after a clean reset. The user's passwd home points elsewhere from the
# directory containing the valid authorized_keys file.
set -eu

sudo docker exec --user root mh-server-8 sh -lc '
  grep -q "^deploy:x:1000:1000::/home/deploy:/bin/bash$" /etc/passwd
  sed -i "s|^deploy:x:1000:1000::/home/deploy:/bin/bash$|deploy:x:1000:1000::/srv/deploy:/bin/bash|" /etc/passwd
  getent passwd deploy
'

printf '%s\n' '### valid key retained at original home'
sudo docker exec mh-server-8 stat -c '%a %U:%G %n' /home/deploy /home/deploy/.ssh /home/deploy/.ssh/authorized_keys
printf '%s\n' '### triggering the SSH failure'
if sudo docker exec mh-client ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 server8 hostname > /tmp/home-directory-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: authentication unexpectedly succeeded' >&2
  exit 2
fi
grep -q 'Permission denied (publickey)' /tmp/home-directory-preflight.log
printf '%s\n' '### server8 authentication evidence'
sudo docker logs --tail 40 mh-server-8 2>&1 | grep -E 'Connection from|Could not open user|authorized keys|Failed publickey' | tail -n 12
