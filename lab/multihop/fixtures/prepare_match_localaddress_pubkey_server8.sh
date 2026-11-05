#!/bin/sh
# Apply after a clean reset. Public-key auth is disabled only when the
# connection arrives on server8's jump-facing Docker interface.
set -eu

sudo docker exec --user root mh-server-8 sh -lc '
  mkdir -p /etc/ssh/sshd_config.d
  printf "Match LocalAddress 10.201.78.8\n    PubkeyAuthentication no\n" > /etc/ssh/sshd_config.d/90-lab-localaddress.conf
  if ! grep -q "^Include /etc/ssh/sshd_config.d/\\*.conf" /etc/ssh/sshd_config; then
    printf "\nInclude /etc/ssh/sshd_config.d/*.conf\n" >> /etc/ssh/sshd_config
  fi
  /usr/sbin/sshd -t -f /etc/ssh/sshd_config
  kill -HUP 1
'

printf '%s\n' '### effective auth without local-address context'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7 | grep '^pubkeyauthentication '
printf '%s\n' '### effective auth with actual local-address context'
sudo docker exec mh-server-8 /usr/sbin/sshd -T -C user=deploy,host=server8,addr=10.201.78.7,laddr=10.201.78.8,lport=22 | grep '^pubkeyauthentication '

if output=$(sudo docker exec mh-client ssh -o BatchMode=yes -o ConnectTimeout=4 server8 hostname 2>&1); then
  printf 'unexpected_success=%s\n' "$output" >&2
  exit 2
else
  status=$?
  printf 'preflight_exit=%s output=%s\n' "$status" "$output"
  case "$output" in
    *"Permission denied ()"*|*"Permission denied (publickey)"*) ;;
    *) printf '%s\n' 'fixture invalid: expected a public-key denial' >&2; exit 2 ;;
  esac
fi
