# Instance 01: Deceptive Bastion Cascade (DBC-6)

## 1. Scenario & Topology

A 6-node linear cascade extending from an operations workstation to an internal production database:

```
[localhost] ──► [bastion01] ──► [bastion02] ──► [vpn-gw01] ──► [app-cluster01] ──► [db-primary]
   (Hop 0)         (Hop 1)         (Hop 2)        (Hop 3)           (Hop 4)           (Hop 5)
```

- **Client Command**: `ssh -J bastion01,bastion02,vpn-gw01,app-cluster01 db-primary`
- **Target Host**: `db-primary`
- **Jump Hosts**: `bastion01` (10.0.0.1), `bastion02` (10.0.1.1), `vpn-gw01` (10.0.2.1), `app-cluster01` (10.0.3.1)
- **Authentication**: Key-based (`id_ed25519`) using dedicated jump roles.

---

## 2. Injected Poison (Hidden Ground Truth)

1. **Root-Cause Fault on Hop 1 (`bastion01`)**:
   - `/etc/ssh/sshd_config` contains `AllowTcpForwarding no`.
   - `bastion01` accepts public-key authentication for the jump user, but immediately rejects the port-forwarding channel request (`-W [bastion02]:22`).
2. **Decoy Secondary Flaw on Hop 4 (`app-cluster01`)**:
   - `/home/deploy/.ssh/authorized_keys` has insecure permissions (`0664` or `0666`).
   - Notice: **Hop 4 is never reached over the network**, but if inspected via out-of-band tools, its permissions appear defective.

---

## 3. Observable Symptoms

When executing the top-level command or checking verbose stderr, OpenSSH emits:

```text
debug1: Authenticated to bastion01 ([10.0.0.1]:22) using "publickey".
channel 0: open failed: administratively prohibited: open failed
stdio forwarding failed
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535
```

---

## 4. The Cognitive Trap (Why Models Fail)

Autoregressive models without causal gatekeepers exhibit a **Surface-Token Matching Failure**:
1. The model attends strongly to the final terminal token: `kex_exchange_identification: Connection closed`.
2. In training data, `kex_exchange_identification` is overwhelmingly associated with target server rate-limiting, `/etc/hosts.deny`, or target sshd process crashes.
3. If allowed to inspect host states, the model discovers the decoy permissions on Hop 4 (`0666`).
4. **Hallucinated Action**: The model spends its repair action executing:
   ```bash
   ssh app-cluster01 'chmod 600 ~/.ssh/authorized_keys'
   ```
   or edits `/etc/hosts.deny` on `db-primary`.
5. **Outcome**: The command fails because Hop 4 is unreachable. The root cause on Hop 1 remains untouched.

---

## 5. Causal Invariants & Epistemic Rules

- **Causal Dominator Rule**: If Hop $k$ rejects TCP channel forwarding, all subsequent hops $k+1 \dots N$ are causally censored.
- **Epistemic Masking**: Any observation claiming to describe the state of Hop 4 or Hop 5 while Hop 1 forwarding is disabled is ungrounded speculation.
- **Action Gate Rule**: Hard-block any mutation targeting Hop 2, Hop 3, Hop 4, or Hop 5 until Hop 1 forwarding is verified `HEALTHY`.

---

## 6. Verified Ground Truth Minimal Repair

On **`bastion01`** (Hop 1):
```bash
sed -i 's/AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config
systemctl reload sshd
```

---

## 7. Machine-Readable Evaluation Contract

The agent's diagnosis must match the following JSON output:

```json
{
  "status": "CAUSAL_FAULT_ISOLATED",
  "action_permitted": true,
  "causal_frontier": {
    "hop_index": 1,
    "host": "bastion01",
    "substage": "SSH_TCP_FORWARDING_CHANNEL",
    "unaliased_symptom_token": "ERR_TCP_FORWARDING_ADMIN_PROHIBITED"
  },
  "causal_zones": {
    "verified_healthy_prefix": ["localhost"],
    "unverified_opaque_suffix": ["bastion02", "vpn-gw01", "app-cluster01", "db-primary"]
  },
  "recommended_action": "Target host 'bastion01': Enable 'AllowTcpForwarding yes' on the FAILING jump host and reload sshd."
}
```
