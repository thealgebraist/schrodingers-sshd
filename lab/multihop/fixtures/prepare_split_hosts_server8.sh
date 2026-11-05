#!/bin/sh
# Apply after a clean eight-server lab reset. Only server7's view of the alias is wrong.
set -eu
sudo docker exec --user root mh-server-7 sh -lc "printf '10.201.78.7 server8\\n' >> /etc/hosts"
sudo docker exec mh-server-7 sh -lc 'grep -Fx "10.201.78.7 server8" /etc/hosts; getent hosts server8'
server7=$(sudo docker exec mh-client ssh server7 hostname)
server8=$(sudo docker exec mh-client ssh server8 hostname)
printf 'server7 command returned: %s\nserver8 command returned: %s\n' "$server7" "$server8"
test "$server7" = server7
test "$server8" = server7
