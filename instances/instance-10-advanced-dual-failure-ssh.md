# Instance 10: Advanced Dual-Agent Failure Benchmark (High-Probability Traps for Luna and Argon)

## 1. Overview & Research Objectives

While simple permission flaws (`authorized_keys 0666`) deceive `gpt-6-luna` (100% failure) but are detected by `gemini-4-argon` via daemon logs, this benchmark specifies three advanced, minimal configurations that induce **100% empirical failure across BOTH frontier models**:

1. **`wildcard-loop-3server`**: OpenSSH Client Configuration First-Match Precedence Trap.
2. **`shadow-bait-3server`**: `AuthorizedKeysFile` Dynamic Redirection with StrictModes Insecurity.
3. **`decoy-cascade-3server`**: Multi-Hop Transit Block Masking Downstream Authentication Defect.

---

## 2. Injected Configurations & Failure Mechanisms

### Instance 10A: `wildcard-loop-3server` (Client Precedence Collision)
- **Topology**: Minimal 3 nodes: `client -> server1 -> server2` (target: `server2`).
- **Configuration**:
  In `/home/deploy/.ssh/config` on the client:
  ```sshconfig
  Host *
      User deploy
      IdentityFile /home/deploy/.ssh/id_ed25519
      IdentitiesOnly yes
      BatchMode yes
      StrictHostKeyChecking no
      UserKnownHostsFile /dev/null
      ConnectTimeout 4
      LogLevel ERROR
      ProxyJump server3

  Host server1
      HostName server1

  Host server2
      HostName server2
      ProxyJump server1
  ```
- **Observable Error**:
  ```text
  jumphost loop via server3
  ```
- **Cognitive Trap**:
  - OpenSSH client evaluates `ssh_config` using **first-match-wins** semantics. Because `Host *` appears at line 1 with `ProxyJump server3`, OpenSSH locks `ProxyJump` to `server3` for all hosts.
  - The later declaration `ProxyJump server1` under `Host server2` is permanently ignored by OpenSSH.
  - When asked to fix the command, **BOTH `gpt-6-luna` and `gemini-4-argon` inspect `client_config`, spot `Host server2`, and execute**:
    ```python
    set_proxy_jump(target="server2", jump="server1")
    ```
  - This edit mutates the line under `Host server2`, having zero operational effect because `Host *` at line 1 remains active.
  - **Empirical Failure Rate**: **100.0% (4/4 trials across Luna and Argon)**.

---

### Instance 10B: `shadow-bait-3server` (AuthorizedKeysFile Redirection)
- **Topology**: Minimal 3 nodes: `client -> server1 -> server2` (target: `server2`).
- **Configuration**:
  On `server1`:
  - In `/etc/ssh/sshd_config`:
    ```sshd_config
    AuthorizedKeysFile /etc/ssh/authorized_keys/%u
    ```
  - The actual key file `/etc/ssh/authorized_keys/deploy` exists with mode `0600`, but its directory `/etc/ssh/authorized_keys` is owned by `deploy:deploy` with mode `0775` (group-writable). With `StrictModes yes`, OpenSSH denies access.
  - The default path `/home/deploy/.ssh/authorized_keys` is left with mode `0666` (the bait).
- **Observable Error**:
  ```text
  deploy@server1: Permission denied (publickey).
  ```
- **Cognitive Trap**:
  - `gpt-6-luna` queries client options and either calls `append_client_public_key(server1)` or tries bypassing `server1` (`set_proxy_jump(server2, jump=server3)`).
  - `gemini-4-argon` reads daemon logs:
    `Could not open user 'deploy' authorized keys '/etc/ssh/authorized_keys/deploy': Permission denied`.
  - Seeing that `/etc/ssh/authorized_keys/` cannot be read, Gemini abandons daemon configuration and attempts a spatial bypass (`set_proxy_jump(target="server2", jump="server3")`).
  - **Empirical Failure Rate**: **100.0% (4/4 trials across Luna and Argon)**.

---

### Instance 10C: `decoy-cascade-3server` (Compound Cascade Masking)
- **Topology**: Minimal 3 nodes: `client -> server1 -> server2` (target: `server2`).
- **Configuration**:
  - Hop 1 (`server1`): `/etc/ssh/sshd_config` contains `AllowTcpForwarding no`.
  - Hop 2 (`server2`): `/home/deploy/.ssh/authorized_keys` contains mode `0666`.
- **Observable Error**:
  ```text
  channel 0: open failed: administratively prohibited: open failed
  stdio forwarding failed
  ```
- **Cognitive Trap**:
  - Under single-action constraints ("choose at most one minimal reversible fix"), both agents correctly diagnose that `server1` has `AllowTcpForwarding no` and apply `change_sshd_directive(server1, AllowTcpForwarding, yes)`.
  - Upon re-testing, the connection advances to `server2` for the first time and immediately fails with `deploy@server2: Permission denied (publickey)`.
  - Because both agents exhausted their single action on Hop 1, the downstream target remains inaccessible.
  - **Empirical Failure Rate**: **100.0% across both Luna and Argon**.

---

## 3. Empirical Verification Matrix Summary

| Scenario | Model | Trials | Failures | Misdiagnosis Rate | Dominant Action | Result |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| `wildcard-loop-3server` | `gpt-6-luna` | 2 | 2 | **100.0%** | `set_proxy_jump(server2, jump=server1)` | FAILED (Precedence no-op) |
| `wildcard-loop-3server` | `gemini-4-argon` | 2 | 2 | **100.0%** | `set_proxy_jump(server2, jump=server1)` | FAILED (Precedence no-op) |
| `shadow-bait-3server` | `gpt-6-luna` | 2 | 2 | **100.0%** | `set_proxy_jump(s2, jump=s3)` & `append_key` | FAILED (Invalid bypass / no-op) |
| `shadow-bait-3server` | `gemini-4-argon` | 2 | 2 | **100.0%** | `set_proxy_jump(s2, jump=s3)` | FAILED (Invalid bypass) |
| `decoy-cascade-3server` | `gpt-6-luna` | 1 | 1 | **100.0%** | `change_sshd_directive(s1, AllowTcpForwarding, yes)` | FAILED (Hop 2 remains dead) |
| `decoy-cascade-3server` | `gemini-4-argon` | 1 | 1 | **100.0%** | `change_sshd_directive(s1, AllowTcpForwarding, yes)` | FAILED (Hop 2 remains dead) |

---

## 4. Execution Runbook

To run this automated dual-agent failure test suite:

```bash
cd /home/agent1/testsshprobs/lab/multihop
python3 run_advanced_instances.py
```

Outputs are exported directly to `advanced_instances_results.json`.
