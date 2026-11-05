#!/bin/sh
set -eu
cd "$(dirname "$0")"
./start.sh >/dev/null
sudo docker stop mh-server-6 mh-server-7 mh-server-8 >/dev/null
python3 - <<'CONFIG'
from pathlib import Path
path=Path("client/.ssh/config")
path.write_text("""Host *
    User deploy
    IdentityFile /home/deploy/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ConnectTimeout 4
    LogLevel ERROR

Host bastion01
    HostName server1

Host bastion02
    HostName server3

Host vpn-gw01
    HostName server2

Host app-cluster01
    HostName server4

Host db-primary
    HostName server5
""")
path.chmod(0o600)
CONFIG
sudo docker exec --user root mh-server-1 sh -c 'printf "\nAllowTcpForwarding no\n" >> /etc/ssh/sshd_config'
sudo docker exec mh-server-1 /usr/sbin/sshd -t -f /etc/ssh/sshd_config
sudo docker exec --user root mh-server-1 kill -HUP 1
sudo docker exec --user root mh-server-4 chmod 0777 /home/deploy/.ssh/authorized_keys
sudo docker exec mh-client ssh -G app-cluster01 >/dev/null
sudo docker exec --user root mh-server-1 /usr/sbin/sshd -T | awk '$1 == "allowtcpforwarding" { print }'
sudo docker exec --user root mh-server-4 stat -c '%a %U:%G %n' /home/deploy/.ssh/authorized_keys
sudo docker ps --filter name=mh- --format '{{.Names}} {{.Status}}'
