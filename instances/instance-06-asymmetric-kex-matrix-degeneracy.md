# Instance 06: Asymmetric KEX Matrix Degeneracy

## 1. Scenario & Topology

A 6-node defense-in-depth infrastructure extending from an upgraded developer workstation to an internal Hardware Security Module (HSM):

```
[client-dev01] ──► [core-edge01] ──► [legacy-gw02] ──► [transit-rt03] ──► [hsm-proxy04] ──► [hsm-core]
   (Hop 0)            (Hop 1)           (Hop 2)           (Hop 3)           (Hop 4)          (Hop 5)
```

- **Client**: OpenSSH 9.8p1 (Modern client with post-quantum hybrid KEX enabled by default).
- **Target Host**: `hsm-core` (Hop 5, running OpenSSH 9.8p1).
- **Intermediate Gateways**:
  - `core-edge01`: OpenSSH 9.6p1
  - `legacy-gw02`: Hardware security appliance / DPI transit proxy (OpenSSH 7.4 / custom embedded filter)
  - `transit-rt03`: OpenSSH 8.9p1
  - `hsm-proxy04`: OpenSSH 9.4p1
- **Command**: `ssh -J core-edge01,legacy-gw02,transit-rt03,hsm-proxy04 hsm-core`

---

## 2. Injected Poison (Hidden Ground Truth)

1. **The Invariant Defect**:
   - `client-dev01` and `hsm-core` both support and prioritize hybrid post-quantum key exchange:
     `sntrup761x25519-sha512@openssh.com` and `mlkem768x25519-sha256`.
   - The intermediate jump `legacy-gw02` enforces stateful Deep Packet Inspection (DPI) on forwarded TCP port 22 traffic, but has a hardcoded buffer limit on initial KEX proposal packets (max 2048 bytes) or rejects unrecognized IANA/experimental KEX identifiers.
2. **The Pairwise Verification Illusion**:
   - Direct connection `client -> core-edge01` succeeds (KEX: `curve25519-sha256`).
   - Direct connection `client -J core-edge01 -> legacy-gw02` succeeds (negotiates standard `curve25519-sha256` because `legacy-gw02` advertises only classical algorithms).
   - Direct connection from `legacy-gw02` to `transit-rt03` succeeds.
   - **Composite Failure**: When tunneling the end-to-end SSH handshake from `client-dev01` to `hsm-core` through `legacy-gw02`, the post-quantum KEX payload exceeds the DPI buffer on Hop 2, causing `legacy-gw02` to abruptly reset the TCP stream (`RST`).

---

## 3. Observable Symptoms

Running the composite jump command:

```text
debug1: Authenticated to core-edge01 ([10.0.1.1]:22) using "publickey".
debug1: Authenticated to legacy-gw02 ([10.0.2.1]:22) using "publickey".
debug1: Authenticated to transit-rt03 ([10.0.3.1]:22) using "publickey".
debug1: Authenticated to hsm-proxy04 ([10.0.4.1]:22) using "publickey".
debug1: Connecting to hsm-core [10.0.5.1] port 22.
debug1: SSH2_MSG_KEXINIT sent
debug2: local client KEXINIT proposal: sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256...
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: mlkem768x25519-sha256
debug1: sending SSH2_MSG_KEX_ECDH_INIT (payload size: 1248 bytes)
kex_exchange_identification: read: Connection reset by peer
Connection reset by 10.0.5.1 port 22
```

---

## 4. The Cognitive Trap (Why Frontier Models Fail)

Frontier models (**GPT-6 Astra Ultra**):
1. **Pairwise Test Confirmation Bias**:
   - The agent writes a script to test each hop sequentially. All sequential hops return status 0!
   - Every individual hop authenticates cleanly.
2. **Terminal Token Attribution Error**:
   - The log displays `Connection reset by 10.0.5.1 port 22`.
   - The agent concludes that `hsm-core` (10.0.5.1) is rejecting the connection due to an iptables rule, max concurrent unauthenticated sessions (`MaxStartups`), or TCP wrapper restrictions (`/etc/hosts.deny`).
3. **Hallucinatory Remediation**:
   - The agent attempts to ssh to `hsm-proxy04` and modify the firewall or `sshd_config` on `hsm-core`.
   - It fails to recognize that the reset was injected mid-stream by `legacy-gw02` when processing the 1248-byte ML-KEM payload.
4. **Failure to Restrict Client KEX**:
   - The agent does not test forcing classical key exchange (`-o KexAlgorithms=curve25519-sha256,diffie-hellman-group16-sha512`) from the client workstation.

---

## 5. Causal Invariants & Epistemic Rules

- **End-to-End Handshake Invariant**: In ProxyJump cascades, the outermost SSH transport handshake is negotiated strictly between Hop 0 and Hop $N$. Intermediate hops merely forward raw TCP payload bytes across channel 0.
- **Payload Size Phase Transition**: A connection failure that occurs immediately following `SSH2_MSG_KEX_ECDH_INIT` with payload $> 1000\ \text{bytes}$ while smaller handshake packets succeeded indicates MTU / DPI middlebox truncation.
- **KEX Downgrade Probe Rule**: Before declaring Hop $N$ dead or modifying remote firewalls, probe with classical KEX restriction:
  ```bash
  ssh -o KexAlgorithms=curve25519-sha256 -J ... target
  ```

---

## 6. Verified Ground Truth Minimal Repair

Client-side configuration fix in `~/.ssh/config`:

```sshconfig
Host hsm-core
    ProxyJump core-edge01,legacy-gw02,transit-rt03,hsm-proxy04
    KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
```

Or on `legacy-gw02`: Update DPI packet inspection buffer / disable SSH application layer gateway filtering on port 22 transit streams.

---

## 7. Machine-Readable Evaluation Contract

The agent's diagnosis must identify the transit payload truncation and specify the KEX restriction:

```json
{
  "status": "CAUSAL_FAULT_ISOLATED",
  "action_permitted": true,
  "causal_frontier": {
    "hop_index": 2,
    "host": "legacy-gw02",
    "substage": "SSH_KEX_TRANSPORT_DEGENERACY",
    "unaliased_symptom_token": "ERR_KEX_PAYLOAD_DPI_RESET"
  },
  "causal_zones": {
    "verified_healthy_prefix": ["client-dev01", "core-edge01"],
    "unverified_opaque_suffix": ["transit-rt03", "hsm-proxy04", "hsm-core"]
  },
  "protocol_mismatch": {
    "negotiated_kex": "mlkem768x25519-sha256",
    "failing_packet": "SSH2_MSG_KEX_ECDH_INIT",
    "payload_bytes": 1248,
    "interceptor_node": "legacy-gw02"
  },
  "recommended_action": "Configure client '~/.ssh/config' to restrict KexAlgorithms to 'curve25519-sha256' for 'hsm-core', or disable DPI packet truncation on 'legacy-gw02'."
}
```
