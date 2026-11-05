#!/usr/bin/env python3
"""Create an isolated, adjacent-link SSH chain using real Docker SSH daemons."""
from __future__ import annotations
import os, re, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get("SSH_COVER_LAB", str(REPO / "lab/multihop")))
RUNTIME = Path(os.environ.get("SSH_COMPLEX_RUNTIME", "/tmp/ssh-complex-lab"))
N = int(os.environ.get("SSH_COMPLEX_SERVERS", "64"))
IMAGE = "ssh-multihop-server:local"
WORKERS = int(os.environ.get("SSH_COMPLEX_START_WORKERS", "8"))
# Link 1..4095 map into the private 10.208.0.0/12 space, one /24 per link.
if not 2 <= N <= 4096: raise SystemExit("server count must be 2..4096")

def link_network(index: int) -> str:
    second = 208 + index // 256
    third = index % 256
    return f"10.{second}.{third}.0/24"

def link_ip(index: int, host: int) -> str:
    second = 208 + index // 256
    third = index % 256
    return f"10.{second}.{third}.{host}"

def run(args: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(args, text=True, capture_output=capture)
    if check and p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(args)}\n{p.stderr[-2000:] if p.stderr else ''}")
    return p

# Remove only this lab's containers and networks. Batch requests avoid serial teardown overhead.
containers = run(["sudo","docker","ps","-aq"],check=False).stdout.splitlines()
if containers:
    rows=[line.split() for line in run(["sudo","docker","ps","-a","--format","{{.ID}} {{.Names}}"]).stdout.splitlines()]
    remove=[cid for cid,name in rows if name=="cpx-client" or re.fullmatch(r"cpx-server-\d+",name)]
    if remove: run(["sudo","docker","rm","-f",*remove],check=False)
networks=run(["sudo","docker","network","ls","--format","{{.Name}}"]).stdout.splitlines()
remove_nets=[x for x in networks if x=="cpx-clientnet" or re.fullmatch(r"cpx-link-\d+",x)]
if remove_nets:
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures=[pool.submit(run,["sudo","docker","network","rm",name],check=False) for name in remove_nets]
        for future in as_completed(futures): future.result()
run(["sudo","docker","image","inspect",IMAGE])

RUNTIME.mkdir(parents=True,exist_ok=True)
ssh_dir=RUNTIME/"client"/".ssh"; ssh_dir.mkdir(parents=True,exist_ok=True)
shutil.copyfile(SOURCE/"client"/".ssh"/"id_ed25519",ssh_dir/"id_ed25519")
with (ssh_dir/"id_ed25519.pub").open("w") as pub:
    subprocess.run(["ssh-keygen","-y","-f",str(ssh_dir/"id_ed25519")],check=True,stdout=pub,stderr=subprocess.DEVNULL)
os.chmod(ssh_dir,0o700); os.chmod(ssh_dir/"id_ed25519",0o600); os.chmod(ssh_dir/"id_ed25519.pub",0o644)
config=["Host *","    User deploy","    IdentityFile /home/deploy/.ssh/id_ed25519","    IdentitiesOnly yes","    BatchMode yes","    StrictHostKeyChecking no","    UserKnownHostsFile /dev/null","    ConnectTimeout 20","    LogLevel ERROR"]
for i in range(1,N+1):
    config += ["",f"Host server{i}",f"    HostName server{i}"]
    if i>1: config.append(f"    ProxyJump server{i-1}")
(ssh_dir/"config").write_text("\n".join(config)+"\n")
os.chmod(ssh_dir/"config",0o600)

jobs=[]
with ThreadPoolExecutor(max_workers=WORKERS) as pool:
    jobs.append(pool.submit(run,["sudo","docker","network","create","--internal","--subnet","10.208.0.0/24","cpx-clientnet"]))
    for i in range(1,N):
        jobs.append(pool.submit(run,["sudo","docker","network","create","--internal","--subnet",link_network(i),f"cpx-link-{i}"]))
    for f in as_completed(jobs): f.result()

def launch(i:int)->None:
    name=f"cpx-server-{i}"
    if i==1: network="cpx-clientnet"; ip="10.208.0.3"
    else: network=f"cpx-link-{i-1}"; ip=link_ip(i-1,3)
    run(["sudo","docker","run","-d","--name",name,"--hostname",f"server{i}","--network",network,"--ip",ip,"--network-alias",f"server{i}",
         "--mount",f"type=bind,src={SOURCE/'authorized_keys'},dst=/lab/authorized_keys,readonly",IMAGE])
    if i<N:
        run(["sudo","docker","network","connect","--ip",link_ip(i,2),"--alias",f"server{i}",f"cpx-link-{i}",name])
with ThreadPoolExecutor(max_workers=WORKERS) as pool:
    futures=[pool.submit(launch,i) for i in range(1,N+1)]
    for f in as_completed(futures): f.result()
run(["sudo","docker","run","-d","--name","cpx-client","--hostname","cpx-client","--network","cpx-clientnet","--ip","10.208.0.2",
     "--user","1000:1000","--env","HOME=/home/deploy","--workdir","/home/deploy","--mount",f"type=bind,src={ssh_dir},dst=/home/deploy/.ssh",
     "--entrypoint","/bin/sleep",IMAGE,"infinity"])

def ready(i:int)->None:
    name=f"cpx-server-{i}"
    for _ in range(20):
        p=run(["sudo","docker","exec",name,"/usr/sbin/sshd","-T"],check=False)
        if p.returncode==0: return
        import time; time.sleep(0.25)
    raise RuntimeError(f"sshd did not become ready in {name}")
with ThreadPoolExecutor(max_workers=WORKERS) as pool:
    futures=[pool.submit(ready,i) for i in range(1,N+1)]
    for f in as_completed(futures): f.result()
print(f"Started {N} isolated SSH servers in an adjacent-link topology; client=cpx-client; runtime={RUNTIME}")
