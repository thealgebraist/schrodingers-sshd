#!/bin/sh
# Apply after a clean eight-server lab reset. The current target key is revoked.
set -eu
LAB_ROOT=${SSH_REVOKED_HOST_LAB:-/home/agent1/testsshprobs/lab/multihop}

host_key=$(sudo docker exec mh-server-8 cat /etc/ssh/ssh_host_ed25519_key.pub)
printf '@revoked server8 %s\n' "$host_key" \
  > "$LAB_ROOT/client/.ssh/known_hosts"
chmod 0600 "$LAB_ROOT/client/.ssh/known_hosts"

config="$LAB_ROOT/client/.ssh/config"
tmp_config="$LAB_ROOT/client/.ssh/config.revoked.tmp"
{
  printf '%s\n' 'Host server8' \
    '    StrictHostKeyChecking yes' \
    '    UserKnownHostsFile /home/deploy/.ssh/known_hosts' \
    '    HostKeyAlgorithms ssh-ed25519' ''
  cat "$config"
} > "$tmp_config"
mv "$tmp_config" "$config"
chmod 0600 "$config"

printf '%s\n' '### revoked host-key fingerprint'
printf '%s\n' "$host_key" | ssh-keygen -lf -
printf '%s\n' '### preflight SSH error'
if sudo docker exec mh-client ssh -vvv -o ConnectTimeout=4 server8 hostname \
    > /tmp/revoked-hostkey-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: revoked host key was accepted' >&2
  exit 2
fi
grep -E 'REVOKED HOST KEY DETECTED|Host key verification failed' \
  /tmp/revoked-hostkey-preflight.log | tail -n 6
