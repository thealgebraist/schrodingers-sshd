#!/bin/sh
set -eu
cd "$(dirname "$0")"
sudo docker build -t ssh-diagnosis-server:local image
if sudo docker network inspect ssh-diagnosis-net >/dev/null 2>&1; then
  internal=$(sudo docker network inspect ssh-diagnosis-net --format '{{.Internal}}')
  if [ "$internal" != true ]; then
    echo 'ssh-diagnosis-net exists but is not internal; remove it and retry' >&2
    exit 1
  fi
else
  sudo docker network create --internal ssh-diagnosis-net >/dev/null
fi
for name in ssh-server-a ssh-server-b; do
  sudo docker rm -f "$name" >/dev/null 2>&1 || true
  sudo docker run -d --name "$name" --hostname "$name" --network ssh-diagnosis-net \
    --mount "type=bind,src=$(pwd)/authorized_keys,dst=/lab/authorized_keys,readonly" \
    ssh-diagnosis-server:local >/dev/null
done
sudo docker network inspect ssh-diagnosis-net --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'
