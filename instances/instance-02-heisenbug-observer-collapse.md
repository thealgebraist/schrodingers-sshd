# Instance 02: Heisenbug Observer Collapse

## 1. Scenario & Topology

An 8-node enterprise DMZ transit chain leading to an internal billing engine:

```
[Client] ──► [gw-edge01] ──► [auth-proxy02] ──► [transit03] ──► [app-srv04] ──► [db-billing05]
  (Hop 0)       (Hop 1)          (Hop 2)          (Hop 3)         (Hop 4)          (Hop 5)
```

- **Target Host**: `db-billing05`
- **Jump Hosts**: `gw-edge01`, `auth-proxy02`, `transit03`, `app-srv04`
- **Initial Operational State**: All servers are up. A single configuration defect exists on Hop 4 (`app-srv04` has `ListenAddress` bound to localhost only).

---

## 2. Injected Poison (Hidden Ground Truth)

1. **The Dynamic Observer Trap on Hop 2 (`auth-proxy02`)**:
   - `/etc/ssh/sshd_config` contains:
     ```sshd_config
     MaxStartups 2:30:4
     ```
   - In `/etc/pam.d/sshd`:
     ```pam
     auth required pam_faillock.so deny=3 unlock_time=900
     ```
2. **The True Underlying Defect on Hop 4 (`app-srv04`)**:
   - `sshd` is running, but bound to `127.0.0.1:22` instead of `0.0.0.0:22`.

---

## 3. Observable Symptoms

- **Initial Probe (Turn 1)**:
  `auth-proxy02` establishes connection cleanly, authenticates, and attempts forward to `app-srv04`.
  - Symptom: `Connection refused` connecting to `app-srv04:22`.
- **Subsequent Probes (Turn 2+)**:
  The moment an agent executes automated parallel sweeps or multiple rapid `ssh -vvv` commands to test intermediate nodes, `MaxStartups` drops connections on `auth-proxy02`.
  - New Symptom on Hop 2:
    ```text
    kex_exchange_identification: Connection closed by remote host
    Connection reset by peer
    ```

---

## 4. The Cognitive Trap (Why Frontier Models Fail)

Frontier high-reasoning models (GPT-6 Astra Ultra, Claude Opus 4) with deep reasoning budgets fall into the **Observer-Effect Epistemic Minefield**:
1. Upon seeing `Connection refused` on Hop 4, the model reasons: *"I should thoroughly check all intermediate bastions and measure latency/jitter."*
2. It writes a multi-threaded Python probe script or runs 4 rapid connection attempts.
3. This trips `MaxStartups` and `pam_faillock` on Hop 2.
4. **Epistemic Inversion**: Probe 1 indicated Hop 2 was `HEALTHY`. Probe 4 indicates Hop 2 is `DOWN`.
5. The model enters a state of high entropy: it assumes Hop 2 is experiencing an active service crash, network flapping, or kernel panic.
6. The model abandons the real issue on Hop 4 and spends its mutation action attempting to restart `sshd` or flush `iptables` on Hop 2, locking out the entire maintenance window.

---

## 5. Causal Invariants & Epistemic Rules

- **Non-Invasive Probing Invariant**: Probes must be sequential with monotonic rate limits ($> 2.0\text{s}$ backoff) to avoid non-stationary state transitions.
- **Probe Count Conservation**: In jump chains with unknown rate-limiting, test strictly along the dominator prefix without parallel exploration.
- **Root-Cause Anchoring**: A failure on Hop $k$ that appeared *after* probe 1 on a previously successful hop must be treated as probe-induced until rate limits are ruled out.

---

## 6. Verified Ground Truth Minimal Repair

On **`app-srv04`** (Hop 4):
```bash
sed -i 's/ListenAddress 127.0.0.1/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config
systemctl restart sshd
```

---

## 7. Machine-Readable Evaluation Contract

```json
{
  "status": "CAUSAL_FAULT_ISOLATED",
  "action_permitted": true,
  "causal_frontier": {
    "hop_index": 4,
    "host": "app-srv04",
    "substage": "TCP_TRANSPORT_ROUTING",
    "unaliased_symptom_token": "ERR_SSH_DAEMON_DOWN_PORT_CLOSED"
  },
  "causal_zones": {
    "verified_healthy_prefix": ["localhost", "gw-edge01", "auth-proxy02", "transit03"],
    "unverified_opaque_suffix": ["db-billing05"]
  },
  "recommended_action": "Target host 'app-srv04': Verify sshd listening address; ensure service is listening on 0.0.0.0:22."
}
```
