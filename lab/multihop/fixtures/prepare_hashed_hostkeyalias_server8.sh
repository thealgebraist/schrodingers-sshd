#!/bin/sh
# Apply after a clean reset. Server8's effective trust alias is a hashed entry.
set -eu
LAB_ROOT=${SSH_HASHED_HOST_LAB:-/home/agent1/testsshprobs/lab/multihop}

sudo docker exec mh-client ssh-keygen -q -t ed25519 -N '' -f /tmp/mh-stale-host
stale_key=$(sudo docker exec mh-client cat /tmp/mh-stale-host.pub)
printf 'prod-db %s\n' "$stale_key" > "$LAB_ROOT/client/.ssh/known_hosts"
ssh-keygen -H -f "$LAB_ROOT/client/.ssh/known_hosts" >/dev/null
rm -f "$LAB_ROOT/client/.ssh/known_hosts.old"
chmod 0600 "$LAB_ROOT/client/.ssh/known_hosts"

config="$LAB_ROOT/client/.ssh/config"
tmp_config="$LAB_ROOT/client/.ssh/config.hashed.tmp"
{
  printf '%s\n' 'Host server8' \
    '    HostKeyAlias prod-db' \
    '    StrictHostKeyChecking yes' \
    '    UserKnownHostsFile /home/deploy/.ssh/known_hosts' \
    '    HostKeyAlgorithms ssh-ed25519' ''
  cat "$config"
} > "$tmp_config"
mv "$tmp_config" "$config"
chmod 0600 "$config"

printf '%s\n' '### effective SSH host-key alias'
sudo docker exec mh-client ssh -G server8 | grep '^hostkeyalias '
printf '%s\n' '### hashed known_hosts lookup'
ssh-keygen -F prod-db -f "$LAB_ROOT/client/.ssh/known_hosts"
printf '%s\n' '### preflight SSH error'
if sudo docker exec mh-client ssh -vvv -o ConnectTimeout=4 server8 hostname \
    > /tmp/hashed-hostkey-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: stale host key was accepted' >&2
  exit 2
fi
grep -E 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed' /tmp/hashed-hostkey-preflight.log | tail -n 6
