---
name: ssh-incident-diagnosis
description: Diagnose and safely repair SSH connection failures across direct and ProxyJump paths by separating configuration, transport, key exchange, authentication, forwarding, and command execution. Use when a user reports SSH login, key, agent, host-key, bastion, or multihop failures.
---

# SSH incident diagnosis

Use this skill for SSH failures. Gather evidence before changing client or server configuration, especially when a route contains multiple jump hosts.

## Identify the exact operation

Record the user, target alias, hostname, port, command, exit code, stdout, stderr, and whether the attempt was interactive or used `BatchMode`. A successful TCP probe, host-key scan, authentication, session, and remote command are different success conditions. Define success as the requested operation completing on the intended host.

## Trace the effective client route

Run `ssh -G <alias>` to inspect resolved `hostname`, `user`, `identityfile`, `identitiesonly`, authentication preferences, `proxyjump`, and timeouts. Remember that an earlier broad `Host *` block may set a value before a later target stanza; verify any edit with `ssh -G`.

Run a bounded verbose attempt, for example:

```sh
ssh -vvv -o BatchMode=yes <alias> hostname
```

For `ProxyJump`, determine the last hop that completed authentication and channel setup. Authentication to a jump host and authentication to the final target are separate events. Each jump server must permit the forwarding channel needed to reach the next hop. `AllowTcpForwarding` and `AllowAgentForwarding` are different controls.

## Classify by protocol stage

- Timeout/refusal: investigate DNS, address selection, route, firewall, listener, and network policy.
- Host-key or KEX failure: investigate endpoint identity, key exchange, protocol version, or an earlier proxy channel; do not assume user authentication failed.
- `Permission denied (publickey)`: inspect offered identities, user, server logs, `AuthorizedKeysFile`, ownership/modes, and key options.
- `administratively prohibited` or `stdio forwarding failed`: investigate forwarding/session-channel policy on each jump hop.
- Login succeeds but the command fails or returns unexpected output: inspect forced-command options, shell, command path, and remote process output.

Treat generic client errors as symptoms. They rarely identify the exact hop by themselves.

## Check credentials and server policy without exposing secrets

Use `ssh-add -l` to check agent reachability and loaded keys; an `SSH_AUTH_SOCK` variable can point to a missing socket. `BatchMode` cannot answer passphrase or password prompts. `ssh-keyscan` establishes only that an SSH endpoint answered, not that the user can log in.

On the server, inspect the correct account's home path, `.ssh`, `authorized_keys`, `AuthorizedKeysFile`, `StrictModes`, `PubkeyAuthentication`, and relevant logs. Use `stat` and fingerprints rather than printing private key content. With `StrictModes yes`, writable or wrongly owned home/key paths can cause OpenSSH to reject a key that is present. Key options such as `command=`, `restrict`, or `no-port-forwarding` can change command and forwarding behavior.

## Repair narrowly and verify

1. Preserve the initial logs and exact failure output.
2. Identify the failing stage and hop from client and server evidence.
3. Read the exact setting or metadata before changing it.
4. Make one narrow, reversible, evidence-supported change. Do not replace keys or broadly weaken SSH policy as a guess.
5. For daemon changes, validate with `sshd -t` before a controlled reload.
6. Verify the exact remote command and all previously working control routes.
7. Read back effective client settings or server state and report the result honestly.

If the evidence is ambiguous, state the candidate causes and use another discriminating probe rather than making a speculative repair. Do not claim resolution if verification failed.

## Evaluate agent behavior

For agent benchmarks, score the tool action and verified outcome separately from the final prose. Ask for a concise evidence-linked explanation, but do not request hidden private chain-of-thought. Compare each explanation sentence against the raw tool output; explanations can misquote inspected keys or logs. Keep each run independent: new process and request sequence, `store=false`, no `previous_response_id`, fresh containers/logs, and restored client baseline. Preserve API request/response bodies, usage, IDs, timing, and tool results without logging authorization headers or API keys.

The four-server lab in this repository demonstrated a specific reproducible failure pattern: under the one-diagnostic-call prompt, a world-writable `authorized_keys` file on server2 yielded a 90% wrong-repair rate (18/20) and 100% task-failure rate for GPT-6 Luna at low effort. The model generally changed server4's `ProxyJump` instead of fixing server2's file mode. Treat this as a result for that exact lab and prompt, not as a general error-rate estimate.
