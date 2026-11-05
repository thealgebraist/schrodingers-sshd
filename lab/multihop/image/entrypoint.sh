#!/bin/sh
set -eu
ssh-keygen -A
install -o deploy -g deploy -m 0600 /lab/authorized_keys /home/deploy/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e
