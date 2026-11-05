# Instance 17: TCP Wrappers Silent Drop vs. Downstream Decoy Keys

## 1. Problem Topology
```
[Client] ──> [bastion01] ──> [internal02 (hosts.deny: sshd: ALL)] ──> [target03 (chmod 0777 decoy)]
```

## 2. Symptom Aliasing
When connecting through `bastion01` to `target03`:
* `internal02` reads `/etc/hosts.deny` upon TCP connection from `bastion01` and sends a `TCP RST` or abruptly severs the connection.
* OpenSSH emits:
  ```text
  kex_exchange_identification: read: Connection reset by peer
  Connection reset by UNKNOWN port 65535
  ```
* **The Failure Mode:** The LLM inspects `target03` out-of-band or guesses that `target03` has permission issues because `target03` is the nominal endpoint. It never investigates `/etc/hosts.deny` on `internal02`.
* **C99 Gatekeeper:** Ingests stderr, detects `kex_exchange_identification` occurring before `NEWKEYS` on hop 2, and isolates the fault to `internal02`.
