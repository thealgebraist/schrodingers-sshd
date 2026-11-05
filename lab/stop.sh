#!/bin/sh
set -eu
sudo docker stop ssh-server-a ssh-server-b >/dev/null 2>&1 || true
sudo docker rm ssh-server-a ssh-server-b >/dev/null 2>&1 || true
sudo docker network rm ssh-diagnosis-net >/dev/null 2>&1 || true
