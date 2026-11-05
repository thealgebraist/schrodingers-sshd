#!/bin/sh
# Apply after a clean eight-server lab reset. Keep the collision scoped to server7/server8.
set -eu
python3 - <<'PY'
from pathlib import Path
p = Path("client/.ssh/config")
s = p.read_text()
marker = "Host server7\n"
assert s.count(marker) == 1
s = s.replace(marker, "Host server7 server8\n    ControlMaster auto\n    ControlPath /tmp/mh-collide\n    ControlPersist yes\n\n" + marker, 1)
p.write_text(s)
PY
sudo docker exec mh-client ssh -MNf server7
sudo docker exec mh-client ssh -S /tmp/mh-collide -O check server7
server7=$(sudo docker exec mh-client ssh server7 hostname)
server8=$(sudo docker exec mh-client ssh server8 hostname)
printf 'server7 command returned: %s\nserver8 command returned: %s\n' "$server7" "$server8"
test "$server7" = server7
test "$server8" = server7
