# SSH diagnostic lab

This lab runs two separate Debian SSH servers in Docker containers on a private internal bridge network. It is intended to compare transport failure with client-side authentication failures and an interactive server password prompt.

## Start and inspect

From this directory's parent:

```sh
./lab/start.sh
sudo docker ps --filter network=ssh-diagnosis-net
sudo docker network inspect ssh-diagnosis-net
```

The current live network is `ssh-diagnosis-net` (`bridge`, `internal=true`). The two containers are `ssh-server-a` and `ssh-server-b`, with current addresses `172.19.0.2` and `172.19.0.3`. The exact addresses can change after recreating the network; use Docker inspection rather than assuming they stay fixed.

The lab account is `deploy`. The password `labpass123` is disposable and must only be used inside this isolated lab. No container port is published on the host.

## Reproduced observations

- **Control:** direct key authentication with `lab/client/id_unlocked` succeeds to both containers and runs a remote command.
- **Agent unavailable:** the key is not in the client's default key directory. With `SSH_AUTH_SOCK` pointing at a missing socket, `ssh-add -l` reports `No such file or directory`; SSH reaches the server but fails authentication. Starting an agent, loading the authorized key, and repeating the same command succeeds. The server log records the connection, so this is not a server outage.
- **Passphrase protected key:** `lab/client/id_ed25519` is encrypted with the lab-only passphrase `lab-passphrase`. In batch mode SSH exits with `Permission denied (publickey,password)`; sshd logs show it recognizes the public key, but no signature completes. An interactive retry prompts `Enter passphrase for key` and succeeds after it is entered.
- **Interactive server password:** with no usable key, a normal terminal SSH attempt to Server B prompts `deploy@…'s password:`. Entering the lab-only password succeeds. In `BatchMode=yes`, SSH cannot answer the prompt and exits with an authentication error.
- **Remote unavailable control:** stopping Server B makes an SSH attempt time out. Restarting it restores the password prompt and successful login. A timeout is evidence of a transport/path problem; the auth failures above occur after TCP/SSH reachability is established.

Server logs are available with `sudo docker logs ssh-server-a` and `sudo docker logs ssh-server-b`.

`observations.json` records the tested commands and outputs, including the Python PTY timeout at the password prompt and a stopped-server comparison.

## Luna 6 low evaluation

`luna_trials.json` records nine diagnosis responses obtained with the `gpt-6-luna` Codex task model: SSH-agent and encrypted-key failures, an interactive password case, Python subprocess timeouts with and without captured prompts, misleading outage labels, and sparse reports. It identified the client-side causes in the evidence-rich cases and asked for more evidence in the sparse case; none of these trials blamed a working remote server. The initial agent prompt explicitly said not to assume the server was down, so it is not an unbiased trial.

`evaluate.py` sends the same kind of probes through Python's HTTP client to the Responses API with `reasoning.effort=low`, reading the credential from `key.txt` (or `OPENAI_API_KEY`) without printing it. The API returned HTTP 429 `project_spend_limit_exceeded` before generating any answer, including after the key file was updated. The Responses API model behavior therefore remains untested here.

## Teardown

```sh
./lab/stop.sh
```

This stops and removes only the two lab containers and their private network. It leaves the built image and generated lab keys in place.
