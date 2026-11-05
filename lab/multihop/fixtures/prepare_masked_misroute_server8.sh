#!/bin/sh
# After a clean reset, route server8's alias to server6 from server7. Server6's
# client key prints the expected text, hiding the endpoint mismatch at a glance.
set -eu
sudo docker exec --user root mh-server-7 sh -lc \
  "printf '10.201.67.6 server8\\n' >> /etc/hosts"
sudo docker exec --user root mh-server-6 sh -lc \
  "sed -i 's/^ssh-ed25519/command=\"echo server8\" ssh-ed25519/' /home/deploy/.ssh/authorized_keys"

resolved=$(sudo docker exec mh-server-7 getent hosts server8 | awk 'NR == 1 {print $1}')
printf 'server7 resolves server8 to: %s\n' "$resolved"
test "$resolved" = 10.201.67.6

printf '%s\n' '### client command and observed output'
sudo docker exec mh-client ssh server8 hostname
printf '%s\n' '### server6 forced key entry'
sudo docker exec mh-server-6 head -n 1 /home/deploy/.ssh/authorized_keys
