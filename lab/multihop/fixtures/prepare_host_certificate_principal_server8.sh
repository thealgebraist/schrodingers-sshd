#!/bin/sh
# Apply after a clean eight-server lab reset. The CA key stays inside mh-client.
set -eu
LAB_ROOT=${SSH_HOST_CERT_LAB:-/home/agent1/testsshprobs/lab/multihop}

sudo docker exec mh-client ssh-keygen -q -t ed25519 -N '' -f /tmp/mh-host-ca
sudo docker exec mh-server-8 cat /etc/ssh/ssh_host_ed25519_key.pub \
  | sudo docker exec -i mh-client sh -c 'cat > /tmp/mh-hostkey.pub'

# The host certificate is CA-valid but names the wrong SSH host principal.
sudo docker exec mh-client ssh-keygen -q -s /tmp/mh-host-ca -I lab-server8-host \
  -h -n wrongprincipal -V -5m:+1h /tmp/mh-hostkey.pub
sudo docker exec mh-client cat /tmp/mh-hostkey-cert.pub \
  | sudo docker exec --user root -i mh-server-8 sh -c \
    'cat > /etc/ssh/ssh_host_ed25519_key-cert.pub && chmod 0644 /etc/ssh/ssh_host_ed25519_key-cert.pub'

sudo docker exec --user root mh-server-8 sh -lc \
  "printf '\\nHostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\\n' >> /etc/ssh/sshd_config; /usr/sbin/sshd -t; kill -HUP 1"

ca_public=$(sudo docker exec mh-client cat /tmp/mh-host-ca.pub)
printf '@cert-authority server8 %s\n' "$ca_public" \
  > "$LAB_ROOT/client/.ssh/known_hosts"
chmod 0600 "$LAB_ROOT/client/.ssh/known_hosts"

config="$LAB_ROOT/client/.ssh/config"
tmp_config="$LAB_ROOT/client/.ssh/config.hostcert.tmp"
{
  printf '%s\n' 'Host server8' \
    '    StrictHostKeyChecking yes' \
    '    UserKnownHostsFile /home/deploy/.ssh/known_hosts' \
    '    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com' ''
  cat "$config"
} > "$tmp_config"
mv "$tmp_config" "$config"
chmod 0600 "$config"

sudo docker exec mh-server-8 ssh-keygen -L -f /etc/ssh/ssh_host_ed25519_key-cert.pub
if sudo docker exec mh-client ssh -vvv -o ConnectTimeout=4 server8 hostname \
    > /tmp/host-certificate-preflight.log 2>&1; then
  printf '%s\n' 'fixture invalid: wrong host-certificate principal was accepted' >&2
  exit 2
fi
grep -E 'Certificate invalid|not a listed principal|Host key verification failed' \
  /tmp/host-certificate-preflight.log | tail -n 6
