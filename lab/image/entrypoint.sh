#!/bin/sh
set -eu
rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key.pub
ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
ssh-keygen -q -t rsa -b 3072 -N '' -f /etc/ssh/ssh_host_rsa_key
install -o deploy -g deploy -m 0600 /lab/authorized_keys /home/deploy/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e
