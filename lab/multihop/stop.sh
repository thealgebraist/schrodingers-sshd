#!/bin/sh
set -eu
for name in mh-client mh-server-1 mh-server-2 mh-server-3 mh-server-4 mh-server-5 mh-server-6 mh-server-7 mh-server-8; do
  sudo docker rm -f "$name" >/dev/null 2>&1 || true
done
for net in mh-client-1 mh-1-3 mh-3-2 mh-2-4 mh-4-5 mh-5-6 mh-6-7 mh-7-8; do
  sudo docker network rm "$net" >/dev/null 2>&1 || true
done
