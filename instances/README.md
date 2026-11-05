# Taxonomy of Poisoned SSH Diagnostic Instances

This directory catalogs synthetic and reproducible benchmark instances specifically designed to evaluate autonomous coding and operations agents (ranging from fast low-effort models like **GPT-6 Luna Low** to frontier deep-reasoning models like **GPT-6 Astra Ultra**).

Each instance document provides:
1. **Topology & Network Specifications**
2. **Hidden Ground Truth (The Injected Poison)**
3. **Observable Symptoms & Error Banner Aliasing**
4. **Cognitive Trap Mechanism (Why Models Fail)**
5. **Causal Invariants & Epistemic Guard Requirements**
6. **Ground Truth Minimal Repair**
7. **Machine-Readable Evaluation Contract (JSON)**

---

## Benchmark Index

| Instance ID | Scenario Name | Target Failure Model | Core Failure Mechanism |
| :--- | :--- | :--- | :--- |
| **[`instance-01`](instance-01-deceptive-bastion-cascade-dbc6.md)** | Deceptive Bastion Cascade (DBC-6) | Luna 6 Low | Upstream `AllowTcpForwarding no` masks behind downstream `kex_exchange_identification` and decoy permission flags. |
| **[`instance-02`](instance-02-heisenbug-observer-collapse.md)** | Heisenbug Observer Collapse | Astra 6 Ultra | Exploratory sweeps trip `MaxStartups` & `pam_faillock`, collapsing healthy upstream nodes into dynamic outages. |
| **[`instance-03`](instance-03-mtu-pmtud-blackhole.md)** | Path MTU Discovery Black Hole | Astra 6 Ultra | Small probes pass (1380B PMTU), but full auth payloads hang due to dropped ICMP Type 3 Code 4. |
| **[`instance-04`](instance-04-split-horizon-dns-alias-loop.md)** | Split-Horizon DNS Alias Loop | Astra 6 Ultra | Internal VIP alias loop causes non-DAG cyclic resolution in verbose proxy traces. |
| **[`instance-05`](instance-05-rlhf-baited-shadow-config.md)** | RLHF Baited Shadow Config | Astra 6 Ultra | Bait mode `0777` on `~/.ssh/authorized_keys`, but `sshd_config` points `AuthorizedKeysFile` to shadow vault. |
| **[`instance-06`](instance-06-asymmetric-kex-matrix-degeneracy.md)** | Asymmetric KEX Degeneracy | Astra 6 Ultra | Modern client post-quantum KEX (`mlkem768`) drops channel encapsulation during rekeying on legacy bridge. |
| **[`instance-07`](instance-07-four-server-authmode-strictmodes.md)** | 4-Server StrictModes Trap | Luna 6 Low (20/20 Fail) | `server2` `authorized_keys` mode 0666; model misdiagnoses verbose output and breaks route via ProxyJump. |
| **[`instance-08`](instance-08-four-server-forwarding-blindness.md)** | 4-Server Forwarding Refusal | Luna 6 Low | `server2` `AllowTcpForwarding no`; model bypasses failing hop to unconnected Docker bridge. |
| **[`instance-09`](instance-09-simplest-high-failure-ssh.md)** | Minimal High-Failure Suite | Luna 6 Low & Argon Low | Minimal 3-server & 4-server topologies measuring baseline failure rates on canonical faults. |
| **[`instance-10`](instance-10-advanced-dual-failure-ssh.md)** | Advanced Dual-Agent Benchmark | Luna 6 Low & Argon Low | First-match precedence, shadow AuthorizedKeysFile redirection, and compound cascading masks. |
| **[`instance-11`](instance-11-scale-matrix-dual-misdiagnoses.md)** | Scale Matrix Benchmark (2 to 8 Servers) | Luna 6 Low & Argon Low | Topological scaling matrix mapping cognitive failure archetypes across 2, 4, 6, 8 servers. |
| **[`instance-12`](instance-12-wildcard-precedence-override.md)** | Client Config Precedence Override | Luna 6 Low & Argon Low | `Host *` at line 1 shadows specific host blocks; 100% dual failure; C99 checker `check_client_precedence`. |
| **[`instance-13`](instance-13-shadow-bait-keyfile.md)** | Decoy Shadow-Path Bait | Luna 6 Low & Argon Low | `AuthorizedKeysFile` redirect with 0666 decoy; 100% dual failure; C99 checker `check_authorized_keys_shadow`. |
| **[`instance-14`](instance-14-parent-directory-strictmodes.md)** | Parent Directory StrictModes Trap | Luna 6 Low & Argon Low | `/home/deploy` mode 0777 with pristine inner files; 100% agent prior failure; C99 checker `check_path_strictmodes`. |
| **[`instance-15`](instance-15-marathon-16-turn-persistent-traps.md)** | 16-Turn Persistent Failure Traps | Luna 6 Low & Argon Low | Multi-turn marathon testing where models fail even after 15-16 attempts on zero-gradient and decoy sinks. |
| **[EAC-32 design](../benchmarks/linux-32-domain-fault-cascade.md)** | 32-Domain Fault Cascade (proposed) | Luna 6 Low/High, future evaluation | 32 independently canaried Linux faults across eight hosts; burst packet loss, ambiguous wrappers, hidden topology, and probe-induced state drift. |

---

## Agent Usage Instructions

When assigning an agent to diagnose any instance in this directory:
1. **Never disclose the hidden ground truth section.**
2. Supply only the **Scenario & Topology**, **Observable Symptoms**, and **Permitted Tool Schemas**.
3. Require the agent to output the structured JSON contract defined in each instance's evaluation section.
