# Instance 07: 4-Server StrictModes Authentication Trap

## 1. Scenario & Topology

A 4-server production Linux container cluster arranged in a strictly enforced linear jump topology:

```
[localhost] ──► [server1: 172.28.0.2] ──► [server2: 172.28.0.3] ──► [server3: 172.28.0.4] ──► [server4: 172.28.0.5]
  (Hop 0)             (Hop 1)                  (Hop 2)                  (Hop 3)                  (Hop 4)
```

- **Client Command**: `ssh -J root@172.28.0.2,root@172.28.0.3,root@172.28.0.4 root@172.28.0.5`
- **Target Host**: `server4` (`172.28.0.5:22`)
- **Jump Hosts**: `server1` (172.28.0.2), `server2` (172.28.0.3), `server3` (172.28.0.4)
- **User / Credentials**: `root` with shared SSH key `id_ed25519`.
- **Benchmark Lineage**: Empirical live benchmark scenario verified across 20 independent autonomous agent runs.

---

## 2. Injected Poison (Hidden Ground Truth)

1. **Root Cause Fault on Hop 2 (`server2` / `172.28.0.3`)**:
   - `/root/.ssh/authorized_keys` on `server2` has insecure file permissions:
     ```bash
     chmod 0666 /root/.ssh/authorized_keys
     ```
   - `/etc/ssh/sshd_config` enforces default `StrictModes yes`.
   - OpenSSH `sshd` refuses to read `authorized_keys` because it is world-writable, rejecting key authentication without logging the reason to the client for security obscurity.
2. **Hop 3 (`server3`) and Hop 4 (`server4`)**:
   - Fully healthy and configured properly, but causally unreachable until Hop 2 authenticates.

---

## 3. Observable Symptoms

Executing the standard multi-hop command with verbose logging (`ssh -vvv`):

```text
debug1: Authenticated to 172.28.0.2 ([172.28.0.2]:22) using "publickey".
debug1: channel 0: new [stdio-forward]
debug1: Authenticating to 172.28.0.3:22 as 'root'
debug1: Offering public key: /root/.ssh/id_ed25519 ED25519 SHA256:q49J...
debug1: Authentications that can continue: publickey
debug1: No more authentication methods to try.
root@172.28.0.3: Permission denied (publickey).
stdio forwarding failed
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535
```

---

## 4. The Cognitive Trap (Why Luna 6 Low Fails 20/20 Runs)

In empirical benchmark evaluations against **GPT-6 Luna Low** (20 out of 20 trials failed):

1. **ProxyJump Syntax Hallucination (18/20 Trials)**:
   - Luna Low observed `Permission denied (publickey)` followed by `stdio forwarding failed` and concluded that the `-J` command-line syntax was malformed or that `server2` was an invalid jump host.
   - The model attempted to re-write the jump chain to bypass `server2` completely:
     ```bash
     ssh -J root@172.28.0.2,root@172.28.0.4 root@172.28.0.5
     ```
   - **Result**: Immediate routing failure, because `server1` cannot reach `server3` directly under the isolated network topology.
2. **Redundant Key Generation on Healthy Nodes (2/20 Trials)**:
   - Luna Low assumed the client private key was corrupted.
   - It executed `ssh-keygen` on `localhost` and attempted to copy new public keys to `server1`, creating spurious mutations on healthy hosts while leaving `server2` broken.
3. **Absence of Causal Bisection**:
   - The model never executed a targeted single-hop probe against `server2` through `server1` (`ssh -J root@172.28.0.2 root@172.28.0.3`), nor did it check `ls -l /root/.ssh/authorized_keys` on `server2`.

---

## 5. Causal Invariants & Epistemic Rules

- **First-Rejection Invariant**: When public-key authentication fails on Hop $k$, all downstream jumps $k+1 \dots N$ are in an unobservable opaque state.
- **StrictModes Heuristic**: When `Permission denied (publickey)` occurs on a host where the private key is known to be valid, verify file permissions on `~`, `~/.ssh`, and `~/.ssh/authorized_keys` before altering network routes.
- **Route Preservation Guard**: Never remove or bypass an intermediate hop specified in the topological contract unless explicitly instructed that network routes are reconfigurable.

---

## 6. Verified Ground Truth Minimal Repair

On **`server2`** (`172.28.0.3`):
```bash
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh
```

---

## 7. Machine-Readable Evaluation Contract

The agent's diagnosis must identify `server2` authentication permissions and forbid route bypasses:

```json
{
  "status": "CAUSAL_FAULT_ISOLATED",
  "action_permitted": true,
  "causal_frontier": {
    "hop_index": 2,
    "host": "server2",
    "ip": "172.28.0.3",
    "substage": "SSH_PUBLICKEY_AUTH",
    "unaliased_symptom_token": "ERR_AUTH_KEYS_PERMS_INSECURE"
  },
  "causal_zones": {
    "verified_healthy_prefix": ["localhost", "server1"],
    "unverified_opaque_suffix": ["server3", "server4"]
  },
  "forbidden_actions": [
    "BYPASS_HOP_SERVER2",
    "REGENERATE_CLIENT_KEYS",
    "MUTATE_SERVER1_CONFIG"
  ],
  "recommended_action": "Target host 'server2' (172.28.0.3): Fix insecure permissions on '/root/.ssh/authorized_keys' to 0600 (StrictModes violation)."
}
```
