# Instance 05: RLHF Baited Shadow Config

## 1. Scenario & Topology

A 5-node security-hardened transit chain terminating at an internal crypto vault:

```
[ops-workstation] ──► [bastion-ext] ──► [sec-proxy01] ──► [vault-bridge] ──► [crypto-vault]
     (Hop 0)             (Hop 1)           (Hop 2)            (Hop 3)           (Hop 4)
```

- **Client Command**: `ssh -J bastion-ext,sec-proxy01,vault-bridge crypto-vault`
- **Target Host**: `crypto-vault` (10.10.40.10)
- **Jump Hosts**: `bastion-ext` (10.10.10.1), `sec-proxy01` (10.10.20.1), `vault-bridge` (10.10.30.1)
- **User Role**: `vault-admin` across all jumps.

---

## 2. Injected Poison (Hidden Ground Truth)

1. **The RLHF Bait Flaw on Hop 3 (`vault-bridge`)**:
   - `/home/vault-admin/.ssh/authorized_keys` exists with blatantly illegal permissions:
     ```bash
     chmod 0777 /home/vault-admin/.ssh/authorized_keys
     chmod 0777 /home/vault-admin/.ssh
     ```
   - In training data distributions, world-writable `authorized_keys` with `StrictModes yes` is the #1 most common SSH tutorial bug.
2. **The True Underlying Root Cause on Hop 3 (`vault-bridge`)**:
   - In `/etc/ssh/sshd_config`, the system administrator configured a centralized path:
     ```sshd_config
     AuthorizedKeysFile /var/run/ssh_vault/%u/authorized_keys
     ```
   - In `/var/run/ssh_vault/vault-admin/`:
     - The directory is owned by `vault-admin:vault-admin` with mode `0775` (group-writable).
     - Because `StrictModes yes` is enabled, OpenSSH rejects reading `/var/run/ssh_vault/vault-admin/authorized_keys` due to insecure parent directory permissions owned by non-root.
     - The standard `/home/vault-admin/.ssh/authorized_keys` file is completely ignored by the active daemon.

---

## 3. Observable Symptoms

Running `ssh -vvv -J bastion-ext,sec-proxy01,vault-bridge crypto-vault` outputs:

```text
debug1: Authenticated to bastion-ext ([10.10.10.1]:22) using "publickey".
debug1: Authenticated to sec-proxy01 ([10.10.20.1]:22) using "publickey".
debug1: Authenticating to vault-bridge:22 as 'vault-admin'
debug1: Offering public key: /home/ops/.ssh/id_ed25519 ED25519 SHA256:7uK8...
debug1: Authentications that can continue: publickey,password
debug1: No more authentication methods to try.
vault-admin@vault-bridge: Permission denied (publickey,password).
stdio forwarding failed
kex_exchange_identification: Connection closed by remote host
```

When an agent executes out-of-band inspection (`ls -ld ~/.ssh ~/.ssh/authorized_keys`) on `vault-bridge`, it sees:
```text
drwxrwxrwx 2 vault-admin vault-admin 4096 Oct 26 12:00 /home/vault-admin/.ssh
-rwxrwxrwx 1 vault-admin vault-admin 1024 Oct 26 12:00 /home/vault-admin/.ssh/authorized_keys
```

---

## 4. The Cognitive Trap (Why Frontier Models Fail)

Frontier reasoning models (**GPT-6 Astra Ultra** and Claude 3.5 Sonnet / Opus class):
1. **Strong RLHF Prior Latching**: The agent inspects the file tree, spots `rwxrwxrwx` permissions on `~/.ssh/authorized_keys`, and triggers an immediate heuristic match:
   > *"Classic SSH StrictModes bug: authorized_keys is mode 0777. Must be 0600, and ~/.ssh must be 0700."*
2. **Premature Action Execution**:
   The model executes:
   ```bash
   chmod 700 /home/vault-admin/.ssh && chmod 600 /home/vault-admin/.ssh/authorized_keys
   ```
3. **The Astray Reasoning Spiral**:
   The model re-tests the connection. The authentication **still fails** with `Permission denied (publickey)`.
   Because the model "fixed" the obvious permission bug, it now hallucinates complex, non-existent errors:
   - It assumes the client's public key fingerprint is corrupt or mismatched.
   - It generates a new keypair, appends it to `/home/vault-admin/.ssh/authorized_keys`, and re-tests.
   - It investigates PAM modules (`/etc/pam.d/sshd`) or checks SELinux contexts.
   - It exhausts its reasoning token budget ($5.00+ in FLOPs) without ever querying the active SSH runtime configuration.

---

## 5. Causal Invariants & Epistemic Rules

- **Daemon Ground Truth Invariant**: The filesystem state in `~/.ssh` is epistemic noise unless validated against `sshd -T -C user=vault-admin,host=10.10.30.1,addr=10.10.20.1`.
- **Runtime Configuration Precedence**: If `AuthorizedKeysFile` or `AuthorizedKeysCommand` overrides the default, mutations to `~/.ssh/authorized_keys` are strictly prohibited (no-op side effects).
- **Ownership Hierarchy Rule**: For any custom `AuthorizedKeysFile`, every parent directory up to `/` must be owned by `root` and not group-writable.

---

## 6. Verified Ground Truth Minimal Repair

On **`vault-bridge`** (Hop 3):
```bash
# Correct permissions on the actual effective authorized_keys store:
chown root:root /var/run/ssh_vault
chmod 755 /var/run/ssh_vault
chown root:root /var/run/ssh_vault/vault-admin
chmod 755 /var/run/ssh_vault/vault-admin
chmod 644 /var/run/ssh_vault/vault-admin/authorized_keys
```

---

## 7. Machine-Readable Evaluation Contract

The agent's diagnostic output must isolate the true configuration path and reject the bait:

```json
{
  "status": "CAUSAL_FAULT_ISOLATED",
  "action_permitted": true,
  "causal_frontier": {
    "hop_index": 3,
    "host": "vault-bridge",
    "substage": "SSH_PUBLICKEY_AUTH",
    "unaliased_symptom_token": "ERR_AUTH_KEYS_PATH_OVERRIDDEN_STRICTMODES"
  },
  "causal_zones": {
    "verified_healthy_prefix": ["bastion-ext", "sec-proxy01"],
    "unverified_opaque_suffix": ["crypto-vault"]
  },
  "bait_detected": {
    "decoy_target": "/home/vault-admin/.ssh/authorized_keys",
    "decoy_flaw": "0777_PERMISSIONS",
    "reason_rejected": "sshd_config AuthorizedKeysFile overrides path to /var/run/ssh_vault/%u/authorized_keys"
  },
  "recommended_action": "Target host 'vault-bridge': Fix parent directory ownership and permissions on '/var/run/ssh_vault/vault-admin' to root:root 755."
}
```
