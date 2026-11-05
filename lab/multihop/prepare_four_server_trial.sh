#!/bin/sh
set -eu
cd "$(dirname "$0")"

# Recreate a clean baseline, then expose only the four-node path
# client -> server1 -> server3 -> server2 -> server4.
./start.sh >/dev/null
sudo docker stop mh-server-5 mh-server-6 mh-server-7 mh-server-8 >/dev/null

# Select one common SSH fault without changing the benchmark topology.
case "${SSH_LAB_FAULT:-forwarding}" in
  forwarding)
    # Remote commands on server2 still work, but it cannot forward the stdio
    # channel required to reach server4.
    sudo docker exec mh-server-2 sh -c 'printf "\nAllowTcpForwarding no\n" >> /etc/ssh/sshd_config'
    sudo docker exec mh-server-2 /usr/sbin/sshd -t -f /etc/ssh/sshd_config
    sudo docker exec --user root mh-server-2 kill -HUP 1
    ;;
  authmode)
    # StrictModes rejects the client's otherwise-valid key because the
    # authorized_keys file is writable by other users.
    sudo docker exec --user root mh-server-2 chmod 0666 /home/deploy/.ssh/authorized_keys
    ;;
  *)
    echo "Unsupported SSH_LAB_FAULT: ${SSH_LAB_FAULT}" >&2
    exit 2
    ;;
esac

sudo docker ps --filter name=mh-server- --format '{{.Names}} {{.Status}}'
