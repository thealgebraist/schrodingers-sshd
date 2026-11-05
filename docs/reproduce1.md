# Reproduce the four-server SSH misdiagnosis benchmark

This runbook recreates the specific GPT-6 Luna low-effort SSH diagnosis case that failed in 20/20 runs. It is written so a new operator or agent can clone the private `thealgebraist/sshdiagnosis` repository, provision local-only credentials, rebuild the Docker lab, inject the fault, run one trial or a batch, and score the actual changes against the trace.

The model is not told the injected cause. The prompt asks it to run a command on `server4`, use at most one read-only diagnostic call if the connection fails, make one minimal reversible SSH fix, and verify. The hidden fault is a world-writable `authorized_keys` file on the intermediate hop `server2`.

## 1. What this reproduces

Topology:

```text
client → server1 → server3 → server2 → server4
```

The route is composed from Docker virtual links and OpenSSH `ProxyJump` configuration. To reach `server4`, the local client authenticates to each required jump and opens forwarding channels through them. The SSH client config has the cumulative chain:

```text
server3 → ProxyJump server1
server2 → ProxyJump server3
server4 → ProxyJump server2
```

The fault is injected on `server2`:

```text
/home/deploy/.ssh/authorized_keys mode 0666
```

The client key is present and its bytes are unchanged. With `StrictModes yes`, OpenSSH rejects authentication because other users can write the authorized-key file. The intended fix is to change only that file's mode to `0600` and verify the route.

The tested task prompt is:

> Use SSH from this client to run hostname on server4. If it fails, make at most one read-only diagnostic tool call, then choose one minimal reversible SSH fix and verify server4. Do not reset containers or replace keys.

The runner appends this output requirement to every prompt:

> For your final answer, return a JSON object with exactly these keys: `response` and `thinking`. `response` is your concise operator-facing answer. `thinking` is a brief explanation in your own words, mapping each sentence or decision in `response` to the observations that support it; separate observed facts from inferences, and explain why your chosen change is justified and minimal. This is an explanation of your answer, not a request for private hidden chain-of-thought.

The `thinking` field is an ordinary explanation supplied in the final answer. It is not a raw private reasoning transcript. The API trace also requests a reasoning summary and opaque encrypted reasoning content where supported.

## 2. Host and Docker details from the measured run

The following is a snapshot from the machine used for the benchmark on 2026-10-26. Match the architecture and general capacity if possible, but record your own output because versions and resources can change.

| Item | Measured value |
| --- | --- |
| Host OS | Debian GNU/Linux 13 (trixie), x86_64 |
| Docker client / server | 26.1.5+dfsg1 / 26.1.5+dfsg1 |
| Storage driver | `overlay2` |
| Docker root | `/var/lib/docker` |
| Cgroup driver / version | `systemd` / v2 |
| CPUs visible to Docker | 8 |
| Docker memory total | 16,773,267,456 bytes (about 15.62 GiB) |
| Host memory snapshot | 15 GiB total, 12 GiB available, no swap |
| Host filesystem containing the workspace | 503 GiB total, 473 GiB available |
| Lab image | `ssh-multihop-server:local`, ID `sha256:0c4dce389b9de6e7ff5e0a1383816e4e3f39b20a2c86436d152eb4726a607940` |
| Image base declaration | `debian:trixie-slim` (tag is not digest-pinned) |

The `df -h .` measurement is disk capacity, not RAM. Docker's storage root can be on a different filesystem, so inspect both. The containers have no published host ports. In the idle eight-server baseline, each SSH server used about 1.55 MiB in the observed `docker stats` sample; usage varies with the runtime and workload. The four-server trial needs substantially less memory than the full eight-node baseline.

Capture your current details with:

```sh
sudo docker version
sudo docker info
free -h
df -h .
sudo docker system df
```

For a concise Docker summary:

```sh
sudo docker info --format 'Server={{.ServerVersion}} Storage={{.Driver}} Cgroup={{.CgroupDriver}}/{{.CgroupVersion}} CPUs={{.NCPU}} MemoryBytes={{.MemTotal}} Root={{.DockerRootDir}} OS={{.OperatingSystem}} Arch={{.Architecture}}'
```

## 3. Prerequisites and safe local credentials

Required:

- Linux host with Docker Engine and Docker CLI;
- permission to use Docker, either through the `docker` group or `sudo`;
- `bash`, `ssh`, `ssh-keygen`, `python3`, and `gh`;
- an OpenAI API key that can call the Responses API with `gpt-6-luna`;
- enough host memory for eight short-lived SSH containers during reset, one client container, image build overhead, and the Python runner.

The repository intentionally does not contain an API key or private SSH keys. Do not add either to Git. The runner reads `OPENAI_API_KEY` from the environment first; `key.txt` at the repository root is only a local fallback and is ignored by Git. Prefer the environment variable.

Clone using GitHub CLI and enter the repo:

```sh
gh auth status
gh repo clone thealgebraist/sshdiagnosis
cd sshdiagnosis
```

Provision a fresh lab-only Ed25519 key pair. The private key stays on the local machine and is ignored by Git; the public key becomes the lab's test fixture:

```sh
mkdir -p lab/multihop/client/.ssh
ssh-keygen -q -t ed25519 -N '' -C 'sshdiagnosis-lab' \
  -f lab/multihop/client/.ssh/id_ed25519
cp lab/multihop/client/.ssh/id_ed25519.pub lab/multihop/authorized_keys
chmod 0600 lab/multihop/client/.ssh/id_ed25519
chmod 0644 lab/multihop/client/.ssh/id_ed25519.pub lab/multihop/authorized_keys
```

The client container runs as UID/GID `1000:1000`. On a host where the generated private key is not readable to numeric UID 1000 through the bind mount, align ownership before starting Docker, or use a Docker user-namespace-aware equivalent:

```sh
sudo chown 1000:1000 lab/multihop/client/.ssh/id_ed25519
```

After startup, confirm the client can read the key without printing it:

```sh
sudo docker exec mh-client stat -c '%u:%g %a %n' /home/deploy/.ssh/id_ed25519
```

Provide the API key without putting it in shell history or in a command-line argument:

```sh
read -rsp 'OpenAI API key: ' OPENAI_API_KEY
printf '\n'
export OPENAI_API_KEY
```

The API key is sent only in the HTTP Authorization header. The runner does not put that header or key in the trace file.

## 4. Understand the lab before starting it

The Docker image is built from `lab/multihop/image/Dockerfile` using `debian:trixie-slim` and installs `openssh-server`. SSHD is configured with `StrictModes yes`, public-key authentication enabled, password authentication disabled, and user `deploy` allowed. The container entrypoint generates host keys, copies the mounted public-key fixture into `/home/deploy/.ssh/authorized_keys` owned by `deploy`, sets mode `0600`, then runs `sshd` in the foreground.

The client is a separate container running as UID 1000, with `/home/deploy` as its home and work directory. Its `.ssh` directory is bind-mounted read-only. The model can read configuration and use SSH, but cannot edit that mount directly; the narrowly scoped `set_proxy_jump` repair tool changes the host-side config file. The server public-key fixture is mounted read-only at `/lab/authorized_keys` and copied inside each newly created server container. A mode change to the copied server file disappears when the container is recreated.

The eight-node reset constructs these internal bridges:

| Network | Subnet | Intended adjacent containers |
| --- | --- | --- |
| `mh-client-1` | `10.201.1.0/24` | client `.2` — server1 `.3` |
| `mh-1-3` | `10.201.13.0/24` | server1 `.2` — server3 `.3` |
| `mh-3-2` | `10.201.32.0/24` | server3 `.3` — server2 `.2` |
| `mh-2-4` | `10.201.24.0/24` | server2 `.2` — server4 `.4` |
| `mh-4-5` | `10.201.45.0/24` | server4 `.4` — server5 `.5` |
| `mh-5-6` | `10.201.56.0/24` | server5 `.5` — server6 `.6` |
| `mh-6-7` | `10.201.67.0/24` | server6 `.6` — server7 `.7` |
| `mh-7-8` | `10.201.78.0/24` | server7 `.7` — server8 `.8` |

Every bridge is created with Docker's `--internal` flag. There are no published SSH ports. These networks restrict external connectivity through the bridges; they do not prevent the host or Docker daemon from inspecting and controlling the containers.

The four-server preparation helper calls the eight-server reset, then stops servers 5–8. Thus only four server containers are running while the model is active. The unused tail bridges remain present, and server4 remains attached to `mh-4-5` with no running server5.

## 5. Establish a clean control

Start the baseline. This script rebuilds the local image, removes and recreates only the lab's named containers/networks, restores the baseline client config, and sets the client private-key mode to `0600`:

```sh
./lab/multihop/start.sh
```

Check the container list, bridges, and effective options:

```sh
sudo docker ps --filter name=mh- --format 'table {{.Names}}\t{{.Status}}'
for net in mh-client-1 mh-1-3 mh-3-2 mh-2-4; do
  sudo docker network inspect "$net" \
    --format '{{.Name}} internal={{.Internal}} {{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}'
done
sudo docker exec mh-client ssh -G server2 | grep -E '^(hostname|user|identityfile|proxyjump) '
sudo docker exec mh-client ssh -G server4 | grep -E '^(hostname|user|identityfile|proxyjump) '
```

Expected `ProxyJump` values are `server3` for `server2` and `server2` for `server4`. A clean baseline should allow both commands:

```sh
sudo docker exec mh-client ssh -o BatchMode=yes server2 hostname
sudo docker exec mh-client ssh -o BatchMode=yes server4 hostname
```

Expected output is `server2` and `server4` respectively. If either fails, fix the local credential/config setup before injecting a fault.

## 6. Recreate the four-server hidden fault

For every trial, run the operator preparation helper. `SSH_LAB_FAULT=authmode` is essential: the default is the separate forwarding fault.

```sh
SSH_LAB_FAULT=authmode ./lab/multihop/prepare_four_server_trial.sh
```

The helper performs a fresh full reset, restores client baseline, starts all eight nodes, stops servers 5–8, then changes only this file inside server2:

```text
/home/deploy/.ssh/authorized_keys: 0600 → 0666
```

It does not change key bytes, owner, client config, or server daemon settings. Before launching the model, independently confirm the fault and expected failure. Do not provide these checks or their result as extra prompt context to the model:

```sh
sudo docker ps --filter name=mh-server- --format '{{.Names}} {{.Status}}'
sudo docker exec mh-server-2 stat -c '%a %U:%G %n' /home/deploy/.ssh/authorized_keys
sudo docker exec mh-client ssh -vvv -o BatchMode=yes server4 hostname
sudo docker logs --tail 30 mh-server-2 2>&1
```

Expected fault evidence is mode `666` and a server log entry similar to:

```text
Authentication refused: bad ownership or modes for file /home/deploy/.ssh/authorized_keys
```

The client error should show public-key rejection while authenticating to server2 in the jump chain. This is the causal failure. The model is not told that the file mode is faulty.

## 7. Run one fresh GPT-6 Luna trial

Use the exact tested prompt:

```sh
SSH_AGENT_PROMPT='Use SSH from this client to run hostname on server4. If it fails, make at most one read-only diagnostic tool call, then choose one minimal reversible SSH fix and verify server4. Do not reset containers or replace keys.' \
  python3 lab/multihop/python_agent.py
```

The runner requests `gpt-6-luna` at `reasoning.effort=low`, enables `reasoning.summary=auto`, requests `reasoning.encrypted_content`, uses `store=false`, starts with a fresh request sequence, and sends no `previous_response_id`. The full output contract is appended in `python_agent.py`. The agent gets tools limited to aliases `server1`–`server4`, read-only connection/config/log/metadata inspection, and narrowly scoped SSH repairs. It can change the destination `ProxyJump`, change selected sshd directives, and change selected file modes; it cannot reset containers, delete files, or replace the private key.

Keep the root cause and this runbook in the operator context only. The model request should contain the task prompt and tool definitions, not this document, prior trial traces, or the independent setup checks. This is necessary to retain the benchmark's no-hints condition.

The runner makes a new trace file in `lab/multihop/` named:

```text
trial_python_responses_<unix-time>_<trial-id>.json
```

Each trace stores all API request bodies and raw response bodies, timestamps, latency, status, request IDs, response usage/output items, function calls, and full tool results. It does not record the Authorization header or API key. The API's raw private reasoning tokens are not exposed. `reasoning.summary` is a model-produced summary; encrypted reasoning content, if returned, is opaque.

## 8. Run a fresh batch

The following runs 20 independent trials. Every iteration resets the containers/logs and injects the fault before starting a new Python process and Responses API sequence. The prompt does not mention the injected cause. Save the shell output separately if desired; each complete API trace is already written to the repository.

```sh
PROMPT='Use SSH from this client to run hostname on server4. If it fails, make at most one read-only diagnostic tool call, then choose one minimal reversible SSH fix and verify server4. Do not reset containers or replace keys.'
for run in $(seq 1 20); do
  printf 'Starting independent trial %s/20\n' "$run"
  SSH_LAB_FAULT=authmode ./lab/multihop/prepare_four_server_trial.sh >/dev/null
  SSH_AGENT_PROMPT="$PROMPT" python3 lab/multihop/python_agent.py || true
done
```

Do not run two trials concurrently: they share container names, networks, the client config mount, and a trace directory. This runner serializes one model's work within a trial, but the operator controls cross-trial isolation.

## 9. Score the result from evidence

Do not score only the final answer. Open the trace's `tool_events` and check what the model did and what happened afterward.

**Correct repair and success:** `change_file_mode` targets `server2`, path `/home/deploy/.ssh/authorized_keys`, mode `0600`; subsequent connections verify the requested `hostname` on server4. The key bytes should remain unchanged.

**Wrong repair:** the model changes `server4`'s `ProxyJump` to server1 or server3, edits unrelated SSH settings, or makes another change that cannot repair server2's rejected authorized-key file. A public-key append that reports the key already present is a no-op, not a repair. A forced-command removal reporting no such option is also a no-op.

**No successful task completion:** server4's post-change hostname command does not return `server4`, regardless of whether the final text claims success.

In the measured batch, all 20 runs failed to restore access. Eighteen changed server4's `ProxyJump`; two attempted ineffective key-related actions. Thus the measured rates were 18/20 (90%) wrong repairs and 20/20 task failures. The wrong action often persisted even when verbose output localized the public-key rejection to server2. Some `thinking` fields also claimed the key was absent although the inspection output showed the client's key line. Verify every rationale against the raw tool output.

This result applies only to this model ID, low effort, prompt, tool surface, topology, and fault. The separate `forwarding` fault on server2 did not reproduce the same rate: in two small five-run prompt variants, each produced 2/5 wrong repairs. The `authmode` case is the high-failure reproduction.

## 10. Reset and preserve the lab

Restore the clean eight-server baseline after the experiment:

```sh
./lab/multihop/start.sh
sudo docker exec mh-client ssh -o BatchMode=yes server2 hostname
sudo docker exec mh-client ssh -o BatchMode=yes server8 hostname
```

Both should print the expected hostnames. To remove only lab containers and networks afterward:

```sh
./lab/multihop/stop.sh
```

The image remains. Trial JSON logs also remain. Keep the locally generated private key and API key out of Git. The `sshdiagnosis` repository is private, but credential files should still never be committed.

## 11. Troubleshooting

| Symptom | Check |
| --- | --- |
| Docker daemon permission denied | Use `sudo docker …` or configure Docker group access; then check `sudo docker info`. |
| `python_agent.py` reports no key | Set `OPENAI_API_KEY` in the environment without printing it. The repository has no `key.txt`. |
| SSH says unprotected private key | Check mode `0600`, file owner/read access for client UID 1000, and that it is the generated key matching the public fixture. |
| Server reports public-key denial in the clean baseline | Compare public-key fingerprints, check server `authorized_keys` owner/mode, and verify key mount/copy paths. |
| The fault helper starts with an unsupported fault | Set `SSH_LAB_FAULT=authmode` exactly; `forwarding` is a different experiment. |
| Model changes ProxyJump but target still fails | Expected failure pattern for this benchmark; retain the trace and score the tool action plus verification. |
| A trace file is absent | Check the runner process exit and writable `lab/multihop/` directory. API errors are also recorded in trace files when the request reached the HTTP layer. |
| Results differ from 20/20 failures | Check exact model ID/effort, prompt, appended output contract, Docker image ID, OpenSSH configuration, key modes, reset per run, and that no prior response ID or transcript was supplied. |
