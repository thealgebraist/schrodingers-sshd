# Instance 16: Dual-Fault Priority Cascade (ENOSPC /tmp + StrictModes SSH)

## 1. Problem Statement & Motivation
In real-world Linux infrastructure failures, services rarely fail in sterile isolation. A common operational nightmare is a **compound incident** where a primary system-level catastrophic failure coexists with a secondary service-level configuration error:
1. **Critical System Emergency:** `/tmp` (or the root partition) has **0 bytes available** (`100% full`, `ENOSPC`).
2. **Secondary Service Failure:** OpenSSH rejects authentication due to `StrictModes` permissions on `authorized_keys` (`0666`).

### Why Causal Priority Ordering is Critical
If an automated agent attempts to repair the SSH failure first (e.g. running `sed -i` to update configurations, generating new host keys, or allocating sessions):
* `sed -i` attempts to create a temporary buffer file in `/tmp` and fails with `sed: couldn't write temp file: No space left on device`.
* OpenSSH privilege separation and PAM session managers fail to allocate buffer space.
* Modifying permissions while the storage invariant is violated leaves the system in an unbootable or unmanageable degraded state.

**Ground-Truth Invariant:** The agent **must** restore storage headroom (`clean_temp_storage`) **before** attempting service configuration mutations (`change_file_mode`).

---

## 2. Experimental Setup on Live Linux Fleet
* **Target Container:** `mh-server-1` on private bridge `mh-client-1` (`10.201.1.3`).
* **Fault Injection:**
  ```bash
  # 1. Mount 1M tmpfs on /tmp and fill to 100%
  sudo nsenter -t $PID -m mount -t tmpfs -o size=1M,mode=1777 tmpfs /tmp
  dd if=/dev/zero of=/tmp/overflow.dump bs=1M count=1
  # 2. Overly permissive authorized_keys
  chmod 0666 /home/deploy/.ssh/authorized_keys
  ```
* **Tool Inventory Available to Agent:**
  * `connect(target="server1", verbose=True)`
  * `inspect_server(server="server1", view="disk_space" | "auth_file_metadata" | "logs" | "status")`
  * `clean_temp_storage(server="server1")`
  * `change_file_mode(server="server1", path="/home/deploy/.ssh/authorized_keys", mode="0600")`

---

## 3. Live Empirical Results with Gemini 3.8 Flash

```text
================================================================================
 DUAL-FAULT PRIORITY ORDERING BENCHMARK: ENOSPC /tmp + STRICTMODES SSH
 Target Model: gemini-3.8-flash (Google Generative AI)
================================================================================
Dual fault successfully injected on server1: /tmp is 100% FULL and authorized_keys is mode 0666.

  [Turn 0] Tool Call: inspect_server({'server': 'server1', 'view': 'disk_space'})
           Result: tmpfs 1.0M  1.0M     0 100% /tmp
  [Turn 0] Tool Call: inspect_server({'server': 'server1', 'view': 'auth_file_metadata'})
           Result: 666 deploy:deploy /home/deploy/.ssh/authorized_keys
  [Turn 0] Tool Call: inspect_server({'server': 'server1', 'view': 'logs'})
  [Turn 0] Tool Call: inspect_server({'server': 'server1', 'view': 'status'})
  [Turn 0] Tool Call: connect({'target': 'server1', 'verbose': True})
           Result: Permission denied (publickey)

  [Turn 1] Tool Call: clean_temp_storage({'server': 'server1'})
           Result: SUCCESS (0% used / 1.0M available)

  [Turn 2] Tool Call: change_file_mode({'server': 'server1', 'path': '/home/deploy/.ssh/authorized_keys', 'mode': '0600'})
           Result: SUCCESS (mode 0600)

  [Turn 3] Tool Call: connect({'target': 'server1', 'verbose': False})
           Result: exit_code: 0, stdout: 'server1'

[Turn 4] Agent concluded turns with explanation:
  "Step 1 (Critical System Invariant): Purged overflow dump files from /tmp using clean_temp_storage, restoring disk availability.
   Step 2 (Service Configuration & Security): Corrected file permissions on authorized_keys to 0600 using change_file_mode."

--------------------------------------------------------------------------------
 EXPERIMENT OUTCOME & ORDERING AUDIT:
--------------------------------------------------------------------------------
 End-to-End Verification: PASS (Connected)
 Sequence of Remediation Actions Executed: [
   'clean_temp_storage({"server": "server1"})', 
   'change_file_mode({"mode": "0600", "server": "server1", "path": "/home/deploy/.ssh/authorized_keys"})'
 ]
 >> ORDERING VERDICT: [CORRECT_PRIORITY_ORDER]
    Model correctly cleared critical storage exhaustion (ENOSPC /tmp) BEFORE altering SSH config!
```

---

## 4. Formal Kami & C99 Priority Guarantee

In `kami_ssh_cell.v` and `ssh_diag_cell.c`, priority ordering is guaranteed at the hardware/automata level:
$$\text{rule\_solve\_config} \implies \left(\bm{b} \wedge H_{\text{ENOSPC}} = 0\right)$$

Because the guard on configuration mutation explicitly tests that the critical system bit is clear, the state machine cannot fire configuration mutations while storage headroom is exhausted, formally enforcing the causal dominance theorem:

$$\mathcal{T}(\text{clean\_temp\_storage}) \prec \mathcal{T}(\text{change\_file\_mode})$$
