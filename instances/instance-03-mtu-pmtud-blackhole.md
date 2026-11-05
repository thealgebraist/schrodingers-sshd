# Instance 03: Path MTU Discovery Black Hole

## 1. Scenario & Topology

A hybrid cloud transit network crossing an IPsec VPN tunnel between AWS and an on-premise industrial enclave:

```
[MacBook Client] ──► [aws-transit01] ──► [ipsec-gw02] ──► [onprem-router03] ──► [scada-host04]
    (Hop 0)             (Hop 1)             (Hop 2)             (Hop 3)             (Hop 4)
```

- **Target Host**: `scada-host04`
- **Network Interface MTU**: Client has standard Ethernet MTU `1500`. The IPsec link between `ipsec-gw02` and `onprem-router03` has an effective MTU of `1380` due to encapsulation headers.

---

## 2. Injected Poison (Hidden Ground Truth)

1. **Path MTU Black Hole on Hop 2 / Hop 3 (`ipsec-gw02` / `onprem-router03`)**:
   - The IPsec tunnel MTU is `1380`.
   - The firewall on `onprem-router03` blocks ICMP:
     ```bash
     iptables -A FORWARD -p icmp --icmp-type fragmentation-needed -j DROP
     ```
   - Path MTU Discovery (PMTUD) fails silently: when a packet with the `DF` (Don't Fragment) bit set exceeds 1380 bytes, the router drops it and the ICMP error is discarded.
2. **Payload Size Asymmetry**:
   - Small diagnostic probes (`ssh host exit 0` or TCP 3-way handshakes) send packets of size $120 - 450$ bytes $\implies$ **100% SUCCESS**.
   - Full authentication using modern large credentials (e.g. `ssh-ed25519-cert` with certificate metadata, FIDO2 webauthn assertions, or agent-forwarded keyrings) sends packets of size $1420 - 2100$ bytes $\implies$ **SILENT HANG & TIMEOUT**.

---

## 3. Observable Symptoms

- **Tool Execution 1 (`connect(target='scada-host04', check_reachability=true)`)**:
  - Command: `ssh scada-host04 true`
  - Output: Exit code 0 (Success).
- **Tool Execution 2 (`connect(target='scada-host04', interactive=true)`)**:
  - The client hangs for 60 seconds and eventually terminates with:
    ```text
    debug3: send packet: type 50 [userauth request with cert]
    [Hangs indefinitely...]
    client_loop: send disconnect: Broken pipe
    ```

---

## 4. The Cognitive Trap (Why Frontier Models Fail)

Frontier models (even with self-written Python scripts) fall into the **Bisection Metric Mismatch Trap**:
1. The model writes a Python bisection script using minimal connection probes:
   ```python
   subprocess.run(["ssh", "-o", "ConnectTimeout=3", hop, "true"])
   ```
2. Every intermediate hop ($S_1, S_2, S_3, S_4$) returns **exit code 0**!
3. The model’s chain-of-thought concludes: *"Transport reachability and routing are 100% verified across all hops. Therefore, the failure cannot be network-related."*
4. When the full command fails, the model attributes the timeout to:
   - Target server entropy depletion (`/dev/random` blocked);
   - Target PAM module deadlocks (`pam_systemd` hang);
   - Target sshd process hung or looping.
5. The model wastes its single mutation action restarting `sshd` or editing PAM configurations on `scada-host04`.

---

## 5. Causal Invariants & Epistemic Rules

- **Payload Symmetry Invariant**: A reachability probe is only representative of end-to-end transport if its packet size $\ge$ the negotiated TLS/SSH authentication envelope ($\ge 1420$ bytes).
- **DF Bit & MSS Clamping Check**: When timeouts occur immediately following `SSH2_MSG_USERAUTH_REQUEST` (packet type 50) while TCP 3-way handshake passes, suspect MTU / PMTUD black hole before touching target authentication configs.

---

## 6. Verified Ground Truth Minimal Repair

On the transit gateway (`ipsec-gw02` or `onprem-router03`), enable TCP MSS clamping:
```bash
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```
or adjust MTU on client interface:
```bash
ip link set dev eth0 mtu 1380
```

---

## 7. Machine-Readable Evaluation Contract

```json
{
  "status": "CAUSAL_FAULT_ISOLATED",
  "action_permitted": true,
  "causal_frontier": {
    "hop_index": 2,
    "host": "ipsec-gw02",
    "substage": "TCP_TRANSPORT_ROUTING",
    "unaliased_symptom_token": "ERR_PACKET_DROP_OR_FIREWALL"
  },
  "causal_zones": {
    "verified_healthy_prefix": ["localhost", "aws-transit01"],
    "unverified_opaque_suffix": ["onprem-router03", "scada-host04"]
  },
  "recommended_action": "Enable TCP MSS clamping (--clamp-mss-to-pmtu) or configure MTU 1380 on gateway interface."
}
```
