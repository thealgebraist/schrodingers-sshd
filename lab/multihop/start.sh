#!/bin/sh
set -eu
cd "$(dirname "$0")"
ROOT=$(pwd)
IMAGE=ssh-multihop-server:local
cp "$ROOT/backups/client_config_8hop_baseline" "$ROOT/client/.ssh/config"
chmod 0600 "$ROOT/client/.ssh/id_ed25519"
sudo docker build -t "$IMAGE" image

# This reset is for the test operator. The diagnosis agent must not run it.
for name in mh-client mh-server-1 mh-server-2 mh-server-3 mh-server-4 mh-server-5 mh-server-6 mh-server-7 mh-server-8; do
  sudo docker rm -f "$name" >/dev/null 2>&1 || true
done
for net in mh-client-1 mh-1-3 mh-3-2 mh-2-4 mh-4-5 mh-5-6 mh-6-7 mh-7-8; do
  sudo docker network rm "$net" >/dev/null 2>&1 || true
done
sudo docker network create --internal --subnet 10.201.1.0/24 mh-client-1 >/dev/null
sudo docker network create --internal --subnet 10.201.13.0/24 mh-1-3 >/dev/null
sudo docker network create --internal --subnet 10.201.32.0/24 mh-3-2 >/dev/null
sudo docker network create --internal --subnet 10.201.24.0/24 mh-2-4 >/dev/null
sudo docker network create --internal --subnet 10.201.45.0/24 mh-4-5 >/dev/null
sudo docker network create --internal --subnet 10.201.56.0/24 mh-5-6 >/dev/null
sudo docker network create --internal --subnet 10.201.67.0/24 mh-6-7 >/dev/null
sudo docker network create --internal --subnet 10.201.78.0/24 mh-7-8 >/dev/null

run_server() {
  name=$1
  network=$2
  address=$3
  alias=$4
  sudo docker run -d --name "$name" --hostname "$alias" --network "$network" --ip "$address" --network-alias "$alias" \
    --mount "type=bind,src=$ROOT/authorized_keys,dst=/lab/authorized_keys,readonly" \
    "$IMAGE" >/dev/null
}
run_server mh-server-1 mh-client-1 10.201.1.3 server1
run_server mh-server-3 mh-1-3 10.201.13.3 server3
run_server mh-server-2 mh-3-2 10.201.32.2 server2
run_server mh-server-4 mh-2-4 10.201.24.4 server4
run_server mh-server-5 mh-4-5 10.201.45.5 server5
run_server mh-server-6 mh-5-6 10.201.56.6 server6
run_server mh-server-7 mh-6-7 10.201.67.7 server7
run_server mh-server-8 mh-7-8 10.201.78.8 server8
sudo docker network connect --ip 10.201.45.4 --alias server4 mh-4-5 mh-server-4
sudo docker network connect --ip 10.201.56.5 --alias server5 mh-5-6 mh-server-5
sudo docker network connect --ip 10.201.67.6 --alias server6 mh-6-7 mh-server-6
sudo docker network connect --ip 10.201.78.7 --alias server7 mh-7-8 mh-server-7
sudo docker network connect --ip 10.201.13.2 --alias server1 mh-1-3 mh-server-1
sudo docker network connect --ip 10.201.32.3 --alias server3 mh-3-2 mh-server-3
sudo docker network connect --ip 10.201.24.2 --alias server2 mh-2-4 mh-server-2
sudo docker run -d --name mh-client --hostname mh-client --network mh-client-1 --ip 10.201.1.2 \
  --user 1000:1000 --env HOME=/home/deploy --workdir /home/deploy \
  --mount "type=bind,src=$ROOT/client/.ssh,dst=/home/deploy/.ssh,readonly" \
  --entrypoint /bin/sleep "$IMAGE" infinity >/dev/null

for net in mh-client-1 mh-1-3 mh-3-2 mh-2-4 mh-4-5 mh-5-6 mh-6-7 mh-7-8; do
  sudo docker network inspect "$net" --format '{{.Name}} internal={{.Internal}} {{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}'
done
sudo docker ps --filter name=mh- --format 'table {{.Names}}\t{{.Status}}'
