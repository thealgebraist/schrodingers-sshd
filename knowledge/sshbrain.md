# SSH diagnosis: protocol model, evidence, and repair practice

This document is a field guide for diagnosing OpenSSH failures, especially when a client traverses several `ProxyJump` hosts. It combines protocol-layer reasoning with directly observed results from a disposable Docker lab. Lab-specific observations are labeled as such; a result from one model, prompt, and topology should not be generalized to all SSH incidents.

## 1. Model the connection as stages

An SSH command has several stages. The user-facing error often compresses or obscures which stage failed.

1. **Name and configuration resolution:** The client resolves the alias, hostname, user, port, identity files, proxy settings, and other options. `Host` blocks and included config files can change the effective result.
2. **Transport:** The client establishes TCP to the next endpoint. Timeouts, refusals, routing failures, firewall drops, and DNS problems occur here.
3. **SSH identification and key exchange:** Client and server exchange protocol banners, negotiate algorithms, and verify the server host key. Errors here concern SSH protocol setup or server identity, not the user's public key authentication.
4. **User authentication:** The server evaluates the offered user credentials. Public-key authentication includes a public key offer and a cryptographic signature over the session. The key being listed in `authorized_keys` is necessary but not sufficient: ownership, file modes, key options, account state, and daemon policy also matter.
5. **Session or forwarding channel:** After authentication, a client can request a command session, shell, subsystem, or forwarding channel. The server may allow login while refusing forwarding.
6. **Remote command execution:** The requested program may fail after SSH has authenticated and opened a session. Check the command's exit status and output separately from SSH setup.

An error such as `Permission denied (publickey)` usually means the client reached an SSH server and did not complete a permitted authentication method. It does not by itself mean the password or key bytes are incorrect. `Connection timed out` usually means a transport path did not complete, though timeouts can also result from filtering or an unresponsive service. `Connection refused` generally means the address was reachable but no process accepted that TCP connection, or an active reject was sent. These are tendencies, not proofs; collect the actual verbose trace and server-side evidence.

`ssh-keyscan` obtaining a host key is evidence that an SSH endpoint answered the scan. It is not proof that the intended user can authenticate. Similarly, a TCP health check to port 22 does not prove that a command can run.

## 2. Authentication happens at every jump

`ProxyJump` (`-J`) does not teleport the client to the destination. The local OpenSSH client authenticates to each jump host and asks that host to open a TCP forwarding channel to the next host. The final destination then performs its own authentication. Each hop may use a different hostname, username, key, agent state, `known_hosts` entry, and daemon policy.

For example:

```text
ssh client → server1 → server3 → server2 → server4
```

The client must authenticate to the servers that act as SSH jump hosts, and those hosts must permit the forwarding needed for the next segment. The final server authenticates the user for the requested command. A server can accept a shell session but reject `direct-tcpip` forwarding; in that case the server may be usable interactively while deeper `ProxyJump` routes fail.

OpenSSH implements jump connections using a stream that carries the next SSH connection (commonly through `-W host:port`). A diagnostic such as `channel open failed: administratively prohibited`, `stdio forwarding failed`, or a subsequent `kex_exchange_identification` / `Connection closed by UNKNOWN port 65535` can result from a rejected channel on an intermediate jump. These symptoms identify a forwarding/channel failure somewhere in the chain more reliably than they identify a particular hop. Do not infer that the named final host is at fault just because its alias was the command's target.

`AllowTcpForwarding no` on a jump server can block the channel required to reach a later host. This is distinct from `AllowAgentForwarding`: agent forwarding passes access to an authentication agent; it does not enable TCP forwarding for `ProxyJump`. The two settings solve different problems.

## 3. SSH client configuration can mislead

Inspect the effective configuration, not only the text someone expects SSH to use:

```sh
ssh -G server4
ssh -vvv -o BatchMode=yes server4 hostname
```

`ssh -G` prints the resolved options without connecting. It is useful for checking `hostname`, `user`, `proxyjump`, `identityfile`, `identitiesonly`, authentication choices, and connection timeouts. The verbose connection trace shows which hop is being contacted and where authentication or channel creation stops.

OpenSSH client options are accumulated from command-line arguments and configuration files. For many scalar options, the first value obtained is used. A broad early `Host *` stanza can therefore prevent a later target-specific setting from taking effect. A tool that blindly edits a later `Host server4` stanza may report success while the effective option remains unchanged. Always read back with `ssh -G` after changing a client config.

Other common client-side causes include:

- wrong `IdentityFile` or file unreadable to the user running SSH;
- `IdentitiesOnly yes` limiting SSH to configured keys while the needed key exists only in an agent;
- `SSH_AUTH_SOCK` pointing to a missing or inaccessible agent socket;
- encrypted private key used with `BatchMode=yes`, which prevents answering the passphrase prompt;
- wrong user, port, host alias, or jump chain;
- `ProxyCommand` or `ProxyJump` inherited from an unexpected config stanza;
- public-key offering suppressed by authentication preferences or a client-side key limit.

`ssh-add -l` tests whether the client can talk to its agent and list loaded identities. It does not prove that a server accepts one. `SSH_AUTH_SOCK` is only a path: a nonempty variable can point to a nonexistent socket. `BatchMode=yes` suppresses interactive prompts; its failure can be entirely client-side even when interactive authentication succeeds.

## 4. Server-side public-key checks

For public-key login, check the complete chain of conditions:

- the public-key algorithm is enabled by the client and server;
- the key is offered for the correct account;
- the server recognizes the key and accepts the signature;
- `AuthorizedKeysFile` points to the file being inspected;
- the account's home and `.ssh` path are owned and accessible as expected;
- `authorized_keys` contains the intended key line and permitted options;
- `StrictModes` ownership/mode checks pass;
- `PubkeyAuthentication` and account policy allow public-key login.

With `StrictModes yes`, OpenSSH rejects unsafe ownership or permissions on the user's home, `.ssh` directory, or authorized-key file. In the lab, a correct key in a world-writable `authorized_keys` file (mode `0666`) was rejected. Server logs explicitly said `bad ownership or modes for file /home/deploy/.ssh/authorized_keys`. Changing only the copied file's mode to `0600` repairs that injected case. A mode of `0644` is not world-writable and passed the lab's negative control when ownership was correct.

Do not assume the key is missing just because the client reports `Permission denied`. Compare key fingerprints or public-key blobs using safe metadata tools. Avoid printing or copying private key material. `ssh-keygen -lf authorized_keys` can fingerprint entries, while `stat` establishes owner and mode. The server log can distinguish “key not offered,” “key not found,” “bad ownership or modes,” and other policy rejections.

Authorized-key options can also change behavior:

- `command="..."` forces a command and may make an interactive shell or expected command appear broken;
- `restrict` disables several capabilities, including port forwarding;
- `no-port-forwarding` blocks forwarding for that key;
- a specific forwarding permission may be restored with an appropriate `port-forwarding` option, but only after verifying the installed OpenSSH version and key-option semantics.

If a forced command is active, `hostname` might return a different output or fail even though authentication worked. That is different from an authentication rejection. Make a minimal edit to the exact key line and preserve comments, unrelated options, other authorized keys, owner, and mode.

## 5. Interpret evidence by layer

| Observation | What it supports | What it does not establish |
| --- | --- | --- |
| TCP connection succeeds | The client reached something accepting TCP on that address and port | SSH authentication or command access works |
| `ssh-keyscan` returns a host key | An SSH endpoint answered the scan | User key is accepted or target is the intended machine |
| `Permission denied (publickey)` | SSH authentication was attempted and no method completed | The private key is wrong or the server is down |
| Server log says `bad ownership or modes` | StrictModes rejected an unsafe path/file | The public key is absent |
| Server log says a key was accepted | That server accepted the key for that attempt | A later forwarding request or remote command succeeded |
| `administratively prohibited` on channel open | A server policy rejected a requested channel | Which hop rejected it without per-hop trace/log context |
| `stdio forwarding failed` | A jump channel could not be established | That the target daemon itself is down |
| Interactive passphrase prompt, batch failure | Batch mode could not supply the key passphrase | Remote outage |
| Password prompt interactively, batch failure | The server offers password authentication but batch mode cannot answer | Remote outage |
| Requested command returns expected hostname | End-to-end SSH command execution reached the intended host | Other commands, accounts, or routes necessarily work |

Keep direct observations and inferences distinct. Record the exact command, exit code, stdout, stderr, timestamp, client options, and relevant server log lines. Do not turn a generic message into a specific root cause without evidence.

## 6. Diagnose a serial jump chain as a pass-chain

For a fixed path with hop forwarding/authentication conditions `X1, …, Xd`, a command at depth `d` succeeds only if all required conditions succeed. In a simple single-fault model, a fault at hop `k` blocks every target whose route includes that hop. A target nearer the client may remain reachable.

For target probes at depths 3 and 8, an observation `target3=success, target8=failure` narrows the fault to the suffix or a target-specific condition, but does not identify an exact server among all deeper hops. This is a censored observation: the end-to-end client sees the first failed dependency only through the final command's symptom. Each intermediate probe adds information. With branching or non-monotone behavior (e.g. a forced command makes one remote command fail while forwarding still works), the simple prefix model no longer fully describes the system.

This structure suggests good probes:

1. establish a known-good baseline to the shortest useful target;
2. test progressively deeper endpoints or explicitly test the suspected jump's command and forwarding behavior;
3. use verbose output to identify the last completed stage;
4. correlate with logs on the server that made the relevant policy decision;
5. change one proven root-cause setting and retest both the original target and unaffected controls.

If probes are restricted, record the ambiguity honestly. A request to “guess the most likely fix” cannot create evidence that the topology does not provide.

## 7. Safe repair workflow

1. **Capture baseline:** exact command, effective options, exit code, stdout/stderr, and unaffected controls.
2. **Locate the failing layer:** DNS/config, transport, host-key exchange, authentication, forwarding/session, or command execution.
3. **Locate the failing hop:** use `ProxyJump` trace, per-hop direct checks where accessible, server logs, and network topology.
4. **Inspect before editing:** current directive, file mode/owner, key entry, and competing config values.
5. **Choose the narrowest reversible change:** one setting or one file mode; avoid deleting data, replacing keys, restarting unrelated services, or broad policy relaxation.
6. **Validate syntax before reload:** for sshd configuration, run `sshd -t` with the exact config file. Reload only the intended daemon if needed.
7. **Verify end to end:** rerun the exact command and expected remote action; also recheck previously working targets.
8. **Read back state:** confirm the effective client options or resulting server file/config, and record hashes when preservation matters.
9. **Report honestly:** state what worked, what failed, what changed, and what the evidence cannot decide.

Avoid `chmod -R`, key replacement, blanket `PermitRootLogin yes`, enabling password authentication without a requirement, disabling host-key checks, or restarting all services as default repairs. These broaden access or destroy useful evidence. If a diagnostic experiment requires a risky action, prefer an isolated disposable lab and an explicit rollback path.

## 8. Evidence from the four-server Luna experiment

The tested route was `client → server1 → server3 → server2 → server4`. The model only saw aliases `server1` through `server4`. The target prompt was:

> Use SSH from this client to run hostname on server4. If it fails, make at most one read-only diagnostic tool call, then choose one minimal reversible SSH fix and verify server4. Do not reset containers or replace keys.

The harness appended a general output contract asking for JSON keys `response` and `thinking`. `thinking` was defined as a brief explanation of the response's evidence and decisions, not private hidden reasoning. Every run used `gpt-6-luna` at low effort, `store=false`, a fresh process, and freshly recreated containers and logs.

With server2 `authorized_keys` mode `0666`, OpenSSH's log showed strict-mode rejection. The correct fix was mode `0600` on server2's copied authorized-key file. Across 20 runs, the model never applied that repair and never verified the requested server4 command successfully. In 18 runs it changed server4's `ProxyJump` to server1 or server3, even though the end-to-end chain still required server2 and authentication had failed there. In 2 runs it attempted ineffective key-related changes; the append operation was a no-op because the client key was already present, and a forced-command remover found no forced command. This exact setup yielded an 18/20 wrong-repair rate and 20/20 task-failure rate.

This is useful evidence of a reproducible error pattern in the exact benchmark—not a claim that Luna always misdiagnoses SSH. The rationales sometimes correctly noted the failed hop but still proposed a route change that could not address server-side authentication. In some traces they also claimed the key was absent or different when the tool output showed the client key present. Therefore score the action and verification against raw tool outputs, not only the model's explanation.

For a different fault, `AllowTcpForwarding no` on server2 with a two-target prompt (`server2` and `server4`) produced 2 wrong repairs in 5 runs after adding the explanation contract; the other 3 fixed server2 correctly. A target4-only prompt under the same forwarding fault produced 2 wrong repairs in 5 runs. Prompt and fault details materially affected the result.

## 9. Model trace collection and memory isolation

The Python Responses API harness saves each request body, raw response body, response ID, usage, response output items, request timestamp, latency, HTTP status, request ID, and tool events. It asks for an API reasoning summary and requests encrypted reasoning content where supported. OpenAI does not expose raw private reasoning tokens; encrypted content is opaque. The final JSON `thinking` field is the model's user-facing explanation and should not be conflated with hidden reasoning.

The harness never logs the Authorization header or API key. Full API traces and tool output are important for post-hoc scoring but can contain identifiers, public keys, configuration, and operational details; store them in an appropriately private repository and review them before sharing. Do not include private SSH keys, API credentials, or tokens in a trace archive.

To prevent carryover between test cases, create a new model process and request sequence, omit `previous_response_id`, set `store=false`, reset containers and logs, restore the baseline client configuration, and keep no previous transcript in the prompt. Same-run tool history is intentionally included because it is evidence from that trial. A second agent or worker sharing the same mutable lab is not isolated just because it has a new conversation.

## 10. Common command patterns

```sh
# Effective options without connecting
ssh -G server4

# Detailed client trace; use BatchMode to avoid hidden interactive waits
ssh -vvv -o BatchMode=yes server4 hostname

# Check whether an agent is reachable and which identities it reports
printf '%s\n' "$SSH_AUTH_SOCK"
ssh-add -l

# Inspect server key file ownership/mode and fingerprints
stat -c '%a %U:%G %n' ~/.ssh ~/.ssh/authorized_keys
ssh-keygen -lf ~/.ssh/authorized_keys

# Validate daemon config before a controlled reload
sudo sshd -t -f /etc/ssh/sshd_config
```

Run server commands as the correct account and in the correct container or host. Local `~` means the shell user's home, not necessarily the SSH login user's home. Avoid exposing private-key contents while collecting evidence.
