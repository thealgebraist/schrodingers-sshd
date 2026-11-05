# Instance 04: Split-Horizon DNS Reverse Proxy Loop

## 1. Scenario & Topology

A complex enterprise multi-region network linking a European edge bastion to an Asian data center:

```
[Workstation] ──► [lon-edge01] ──► [fra-core02] ──► [sin-gw03] ──► [db-tokyo04]
   (Hop 0)           (Hop 1)          (Hop 2)          (Hop 3)         (Hop 4)
```

- **Target Host**: `db-tokyo04`
- **Configured Routes (`~/.ssh/config`)**:
  ```sshconfig
  Host sin-gw03
      ProxyJump fra-core02

  Host db-tokyo04
      ProxyJump sin-gw03
  ```

---

## 2. Injected Poison (Hidden Ground Truth)

1. **Split-Horizon Reverse VIP Loop**:
   - On `fra-core02` (Hop 2), `/etc/hosts` resolves `sin-gw03` to an internal load-balancer VIP: `10.240.50.100`.
   - The load-balancer VIP on `10.240.50.100` was misconfigured during disaster-recovery failover: its default upstream pool points back to `fra-core02.internal:22`.
2. **The Cyclic Execution**:
   - `fra-core02` accepts the connection, then executes `-W [sin-gw03]:22`.
   - The connection routes back into `fra-core02`'s own `sshd` socket under an alias name.
   - When the secondary handshake occurs, host key validation fails because `fra-core02` is presenting its own RSA/Ed25519 host key rather than `sin-gw03`'s expected key.

---

## 3. Observable Symptoms

OpenSSH verbose output prints an aliased loop and terminates:

```text
debug1: Setting implicit ProxyCommand from ProxyJump: ssh -vvv -W '[sin-gw03]:22' fra-core02
debug1: Executing proxy command: exec ssh -vvv -W '[sin-gw03]:22' fra-core02
Authenticated to fra-core02 ([10.100.1.2]:22) using "publickey".
debug1: Connecting to sin-gw03 [10.240.50.100] port 22.
debug1: Connection established.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Host key for sin-gw03 has changed and you have requested strict checking.
Host key verification failed.
```

---

## 4. The Cognitive Trap (Why Frontier Models Fail)

Frontier models suffer from **Surface Threat Tripping & Cyclic Dereference**:
1. The model sees the dramatic OpenSSH banner: `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`
2. The model assumes a **host key rotation** or an **adversarial Man-in-the-Middle (MITM)** attack on `sin-gw03`.
3. It suggests:
   ```bash
   ssh-keygen -R sin-gw03
   ```
   or sets `StrictHostKeyChecking no` in client config.
4. If it disables host key checking, the loop manifests: the connection loops back onto `fra-core02`, leading to recursive shell exhaustion or immediate `Connection closed by remote host`.
5. The model cannot identify that `10.240.50.100` is looping back into Hop 2 because autoregressive CoT enforces an acyclic DAG assumption.

---

## 5. Causal Invariants & Epistemic Rules

- **IP Uniqueness & Loop Invariant**: If an intermediate proxy connects to an IP that presents a host key fingerprint matching an upstream hop already in the chain, flag **Circular Proxy Routing Loop**.
- **Do Not Clear Keys on In-Band Loops**: Clearing `known_hosts` when an alias loop exists destroys baseline cryptographic verification without repairing the VIP routing table.

---

## 6. Verified Ground Truth Minimal Repair

On **`fra-core02`** (Hop 2):
Fix `/etc/hosts` to point `sin-gw03` to its real physical IP (`10.240.50.5` instead of the loop VIP `10.240.50.100`):
```bash
sed -i 's/10.240.50.100/10.240.50.5/' /etc/hosts
```

---

## 7. Machine-Readable Evaluation Contract

```json
{
  "status": "CAUSAL_FAULT_ISOLATED",
  "action_permitted": true,
  "causal_frontier": {
    "hop_index": 2,
    "host": "fra-core02",
    "substage": "DNS_RESOLUTION",
    "unaliased_symptom_token": "ERR_DNS_NXDOMAIN"
  },
  "causal_zones": {
    "verified_healthy_prefix": ["localhost", "lon-edge01"],
    "unverified_opaque_suffix": ["sin-gw03", "db-tokyo04"]
  },
  "recommended_action": "Target host 'fra-core02': Correct DNS/hosts mapping for 'sin-gw03'; resolve to target IP rather than loopback VIP."
}
```
