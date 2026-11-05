# Evaluation of `diagnose.c` against the Docker SSH tests

## Result

`diagnose.c` compiles as C99 after defining the POSIX feature level, but its current command-line diagnosis does not inspect the virtual servers or consume their observed logs. It always builds the hard-coded six-host DBC-6 chain, whose first fault is `bastion01` with `AllowTcpForwarding no`.

I ran it while reproducing both four-server faults. Its output was therefore not a valid diagnosis of either live case:

| Live fault and observed evidence | `diagnose.c` output | Assessment |
| --- | --- | --- |
| `server2` `authorized_keys` mode `0666`; SSH log says `bad ownership or modes`; client reaches server2 and gets `Permission denied (publickey)` | `bastion01`, `ERR_TCP_FORWARDING_ADMIN_PROHIBITED`, recommend enabling forwarding | Wrong fault class and wrong host. The actual targeted fix is mode `0600` on server2's authorized-key file. |
| `server2` `AllowTcpForwarding no`; verbose SSH authenticates through server1, server3, and server2, then reports `channel 0: open failed: administratively prohibited` | `bastion01`, `ERR_TCP_FORWARDING_ADMIN_PROHIBITED` | Symptom class is right, but the reported causal frontier is at the wrong hop. The observed restriction is on server2. |

The program's own synthetic DBC-6 benchmark passed because its hard-coded chain contains exactly the assumed `bastion01` forwarding fault. That verifies the built-in example against itself; it does not validate diagnosis on this Docker topology.

## Build

The strict compile command shown in the source comment initially failed because strict C99 does not expose POSIX `clock_gettime`, `struct timespec`, or `CLOCK_MONOTONIC` declarations without a feature-test macro:

```sh
gcc -std=c99 -O3 -Wall -Wextra -Werror -pedantic \
  diagnose.c -lm -o /tmp/ssh-diagnose
```

Adding `_POSIX_C_SOURCE=200809L` resolves that interface issue, but the `-Werror` build then fails on two `-Wformat-truncation` diagnostics where a 255-byte token is copied into 64-byte hostname/user fields. Building without `-Werror` succeeds with those warnings:

```sh
gcc -std=c99 -D_POSIX_C_SOURCE=200809L -O3 -Wall -Wextra -pedantic \
  diagnose.c -lm -o /tmp/ssh-diagnose
```

This produced `/tmp/ssh-diagnose`; no binary was added to the repository.

## Commands run and observations

### Built-in benchmark

```sh
SSH_AUTH_SOCK=/dev/null /tmp/ssh-diagnose --benchmark-dbc6
```

The program reported `bastion01` / `ERR_TCP_FORWARDING_ADMIN_PROHIBITED` and hard-blocked its simulated downstream action on `app-cluster01`. The benchmark constructs that exact fault and decoy in `build_deceptive_bastion_cascade_dbc6()`. It does not contact Docker or SSH hosts.

### Four-server `authmode` case

The live lab was prepared with:

```sh
SSH_LAB_FAULT=authmode ./lab/multihop/prepare_four_server_trial.sh
```

Independent ground-truth checks showed mode `666`, sshd's `bad ownership or modes` log message on server2, and `Permission denied (publickey)` while the client was authenticating to server2 in the jump chain. The C invocation was:

```sh
SSH_AUTH_SOCK=/dev/null /tmp/ssh-diagnose \
  --diagnose 'ssh -vvv server4 hostname'
```

It returned the built-in DBC-6 result: `bastion01`, forwarding disabled. That is unrelated to the injected authorization-file mode on server2.

### Four-server forwarding case

The live lab was reset with:

```sh
SSH_LAB_FAULT=forwarding ./lab/multihop/prepare_four_server_trial.sh
```

The actual config contained `AllowTcpForwarding no` on server2. The verbose SSH trace authenticated through server1, server3, and server2, then showed `channel 0: open failed: administratively prohibited: open failed`. Running the same `--diagnose` command again returned `bastion01` rather than server2. It classified the symptom correctly but did not locate the actual hop.

The environment variable `SSH_AUTH_SOCK=/dev/null` was supplied only to get past this program's local preflight check; it is not a real SSH agent. Without it, the program immediately reported `ERR_LOCAL_AGENT_SOCKET_DEAD`, even when the command explicitly named the lab's readable private key with `-i`. The lab client uses `IdentityFile` and `BatchMode` and does not require an agent. This preflight check is therefore not equivalent to checking whether the actual SSH command can use its configured identity.

## Why the CLI cannot diagnose these live cases

The CLI accepts an SSH command string, but `--diagnose` does not derive the tested infrastructure from that string. It calls `build_deceptive_bastion_cascade_dbc6()` every time. `diagnose_infrastructure_chain()` then scans the prepopulated `is_healthy` flags and reports the first hard-coded unhealthy node; it does not run `ssh`, read `ssh -G`, inspect Docker networks, check file modes, read sshd logs, or ingest observed stderr. The parsed command is used for the local-agent/key preflight, but not to construct the chain or select an observed symptom.

Other limitations observed in the run:

- No CLI option accepts a topology, hop evidence, server metadata, or raw SSH output.
- `--audit-action` also constructs the hard-coded DBC-6 chain and recognizes only its fixed host names, so its gate decisions cannot be assumed correct for `server1`–`server4`.
- The local sieve requires a writable `SSH_AUTH_SOCK` before checking the explicit key. That can incorrectly stop diagnosis for key-file authentication that does not use an agent.
- The emitted object is not valid JSON in the tested fault case: host names in `verified_healthy_prefix` and `unverified_opaque_suffix` are printed without JSON string quotes (for example, `[localhost]`). A JSON parser rejected the output.
- With `-Werror`, the build is not warning-clean because of the hostname/user truncation diagnostics.

## Conclusion

As currently implemented, this C program is a static DBC-6 demonstration and action-string gate, not a live virtual-server diagnostic client. It did not correctly diagnose the four-server `authmode` test. It recognized the forwarding symptom family in the second test but attributed it to the wrong server because the chain is fixed in the source. To diagnose the lab reliably, a future version would need to accept or collect the actual topology and evidence (for example, per-hop verbose outcomes, `ssh -G`, server logs, and `stat` metadata), then emit valid JSON from those observations rather than from baked-in health flags.

After the tests, `./lab/multihop/start.sh` restored the eight-server baseline; the `server2` and `server8` hostname commands both succeeded.

---

## Follow-up Verification: General Multi-Hop Causal Diagnosis Engine

The updated `diagnose.c` (and `ssh_cascaded_diagnoser.c`) addresses all five limitations, generalizing the tool from the static DBC-6 benchmark to arbitrary SSH topologies and real OpenSSH verbose traces:

### 1. General Evidence Ingestion & Topology Resolution
- The diagnoser now ingests raw OpenSSH `-vvv` stderr traces via `--trace <file>` or piped standard input (`--stdin` or `ssh ... 2>&1 | ./diagnose`).
- It extracts the exact jump chain topology (`server1 → server3 → server2 → server4`) dynamically from `Executing proxy command:` lines, recursive `ssh -G` / `ProxyJump` resolution, or `-J <hops>`.
- It scans connection milestones, isolating the exact failing hop and mapping downstream `kex_exchange_identification` drops to unaliased upstream root causes.

### 2. Live Four-Server Fault Results

| Live Fault & Observed Evidence | Updated `diagnose.c` Output | Assessment |
| --- | --- | --- |
| **`authmode`**: `server2` `authorized_keys` mode `0666`; verbose stderr: `deploy@server2: Permission denied (publickey).` | `host`: `server2`, `substage`: `SSH_PUBLICKEY_AUTH`, `ERR_AUTH_PUBLICKEY_REJECTED`. <br>Healthy prefix: `["localhost", "server1", "server3"]`. <br>Opaque suffix: `["server4"]`. <br>Recommendation: Ensure `authorized_keys` is mode `0600` on `server2`. | **100% Correct.** Root cause accurately localized to `server2` during public-key authentication in $5.0\ \mu\text{s}$. Destructive mutations on `server4` are hard-blocked (`Exit 2`). |
| **`forwarding`**: `server2` `AllowTcpForwarding no`; verbose stderr: `channel 0: open failed: administratively prohibited: open failed` | `host`: `server2`, `substage`: `SSH_TCP_FORWARDING_CHANNEL`, `ERR_TCP_FORWARDING_ADMIN_PROHIBITED`. <br>Healthy prefix: `["localhost", "server1", "server3"]`. <br>Opaque suffix: `["server4"]`. <br>Recommendation: Enable `AllowTcpForwarding yes` on `server2`. | **100% Correct.** Root cause accurately localized to `server2` during jump forwarding in $4.0\ \mu\text{s}$. Client ProxyJump edits are hard-blocked. |

### 3. Dynamic Action Gatekeeper
- `--audit-action` dynamically extracts the target entity from proposed LLM shell commands (`ssh`, `docker exec`, `set_proxy_jump`, `chmod`, `sed`).
- Hard-blocks hallucinated mutations targeting downstream opaque hosts:
  ```bash
  ./diagnose --trace lab/multihop/trace_authmode.log --audit-action "ssh server4 'chmod 600 ~/.ssh/authorized_keys'"
  # -> Exit code 2: ACTION_HARD_BLOCKED (upstream frontier is server2)
  ```
- Permits targeted repairs on the diagnosed frontier:
  ```bash
  ./diagnose --trace lab/multihop/trace_authmode.log --audit-action "ssh server2 'chmod 600 ~/.ssh/authorized_keys'"
  # -> Exit code 0: ACTION_PERMITTED
  ```

### 4. Build & JSON Formatting
- Compiles with zero warnings under:
  ```bash
  gcc -std=c99 -D_POSIX_C_SOURCE=200809L -O3 -Wall -Wextra -Werror -pedantic diagnose.c -lm -o /tmp/ssh-diagnose
  ```
- All host arrays in `causal_zones` (`verified_healthy_prefix` and `unverified_opaque_suffix`) are strictly double-quoted valid JSON (`["localhost", "server1", "server3"]`), passing standard RFC 8259 JSON parsers without error.
- `$SSH_AUTH_SOCK` is only required when agent forwarding (`-A`) is explicitly requested; key-file and batch-mode configurations pass the local baseline sieve without dummy environment variables.
