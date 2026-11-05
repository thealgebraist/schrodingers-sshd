# Instance 09: Minimal High-Misdiagnosis SSH Benchmark (Topological Minimization)

## 1. Scenario & Topology Overview

This benchmark establishes the **minimal topological and configuration complexity** required to maximize autonomous diagnostic agent misdiagnosis rates across fast-reasoning models (**OpenAI GPT-6 Luna Low** and **Google Gemini 4 Argon Low**).

We compare three topological tiers:
1. **2-Node Direct Baseline (`authmode-2server`)**:
   ```
   [mh-client] ──────► [mh-server-1] (Target)
   ```
2. **3-Node Minimal Jump Chain (`authmode-3server` & `forwarding-3server`)**:
   ```
   [mh-client] ──────► [mh-server-1] (Jump) ──────► [mh-server-2] (Target)
   ```
3. **4-Node Permuted Jump Chain (`authmode-4server` & `forwarding-4server`)**:
   ```
   [mh-client] ──► [mh-server-1] ──► [mh-server-3] ──► [mh-server-2] ──► [mh-server-4] (Target)
   ```

- **Target Systems**: Debian 13 Linux containers (`OpenSSH_10.0p2`) running on isolated Docker bridge subnets.
- **Client Toolset**: Strictly typed Python execution suite (`ssh_eval_suite.py`) providing standard operational tools: `connect`, `inspect_client`, `inspect_server`, `change_sshd_directive`, `change_file_mode`, `set_proxy_jump`, and `append_client_public_key`.
- **Operational Constraint**: Standard single-turn diagnostic rule:
  > *"Use SSH from this client to run hostname on {target_host}. If it fails, make at most one read-only diagnostic tool call, then choose one minimal reversible SSH fix and verify {target_host}. Do not reset containers or replace keys."*

---

## 2. Injected Faults (Hidden Ground Truth)

We isolate two atomic, single-line configuration defects:
1. **StrictModes Insecurity (`authmode`)**:
   - `authorized_keys` mode set to `0666` (world-writable).
   - Injected on the intermediate transit host (`mh-server-1` in 3-node, `mh-server-2` in 4-node).
   - Ground truth minimal repair: `chmod 0600 /home/deploy/.ssh/authorized_keys`.
2. **TCP Forwarding Denial (`forwarding`)**:
   - `AllowTcpForwarding no` injected into `sshd_config` on the intermediate transit host.
   - Ground truth minimal repair: `change_sshd_directive(host, "AllowTcpForwarding", "yes", reload=True)`.

---

## 3. Empirical Benchmark Matrix (30 Independent Trials)

Evaluated under identical environmental conditions on remote QEMU VM host (`159.195.249.30`):

| Scenario | Topology | Model | Reasoning Tier | Trials | Failures | Misdiagnosis Rate | Dominant Misdiagnosis Failure Mode |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `authmode-2server` | 2-node direct | `gpt-6-luna` | `effort: low` | 3 | 0 | **0.0%** | None (Correctly fixed mode `0600`) |
| `authmode-2server` | 2-node direct | `gemini-4-argon` | `budget: 1024` | 3 | 0 | **0.0%** | None (Correctly fixed mode `0600`) |
| `forwarding-3server` | 3-node 1-hop | `gpt-6-luna` | `effort: low` | 3 | 1 | **33.3%** | `WRONG_PROXYJUMP_BYPASS` (`set_proxy_jump(s2, jump=s2)`) |
| `forwarding-3server` | 3-node 1-hop | `gemini-4-argon` | `budget: 1024` | 3 | 0 | **0.0%** | None (Correctly updated directive to `yes`) |
| **`authmode-3server`** | **3-node 1-hop** | **`gpt-6-luna`** | **`effort: low`** | **3** | **3** | **100.0%** | **`REDUNDANT_KEY_APPEND` (67%) & `WRONG_PROXYJUMP_BYPASS` (33%)** |
| `authmode-3server` | 3-node 1-hop | `gemini-4-argon` | `budget: 1024` | 3 | 0 | **0.0%** | None (Inspects daemon logs directly) |
| `forwarding-4server` | 4-node 3-hop | `gpt-6-luna` | `effort: low` | 3 | 0 | **0.0%** | None (Identified `server2` from verbose trace) |
| `forwarding-4server` | 4-node 3-hop | `gemini-4-argon` | `budget: 1024` | 3 | 0 | **0.0%** | None (Correctly updated directive to `yes`) |
| **`authmode-4server`** | **4-node 3-hop** | **`gpt-6-luna`** | **`effort: low`** | **3** | **3** | **100.0%** | **`WRONG_PROXYJUMP_BYPASS` (67%) & `REDUNDANT_KEY_APPEND` (33%)** |
| `authmode-4server` | 4-node 3-hop | `gemini-4-argon` | `budget: 1024` | 3 | 0 | **0.0%** | None (Inspects daemon logs directly) |
| **`decoy-3server`** | **3-node compound** | **`gpt-6-luna`** | **`effort: low`** | **1** | **1** | **100.0%** | **Single fix leaves downstream target inaccessible** |
| **`decoy-3server`** | **3-node compound** | **`gemini-4-argon`** | **`budget: 1024`** | **1** | **1** | **100.0%** | **Single fix leaves downstream target inaccessible** |

---

## 4. Key Findings: Cognitive Traps & Model Divergence

### 1. Topological Minimization Threshold ($N^* = 3$)
- **2 Nodes is Insufficient for Misdiagnosis**: When $N = 2$ (`client -> server1`), both models achieve **0% failure**. The absence of intermediate transit hops eliminates routing ambiguity and ProxyJump bypass hallucinations.
- **3 Nodes is the Minimal Misdiagnosis Topology**: For `gpt-6-luna`, expanding from 2 to 3 nodes (`client -> server1 -> server2`) triggers an immediate transition from **0% to 100% failure** under `authmode`. The presence of a single intermediate jump node with an alternate jump alias in `config` is sufficient to induce catastrophic misdiagnosis.

### 2. Divergent Diagnostic Heuristics (Luna vs Argon)
- **`gpt-6-luna` (Client-Configuration & Bypass Bias)**:
  - Under `authmode`, Luna observes `deploy@server1: Permission denied (publickey)`.
  - Its dominant reflex is to query `inspect_client(view="effective_ssh_options")`.
  - Because it operates on client options, it latches onto one of two high-frequency pre-training priors:
    1. *Key-Missing Prior*: It assumes the client public key was never installed on `server1` and calls `append_client_public_key(server1)`. Because the file remains mode `0666`, the repair is a complete no-op.
    2. *Spatial Bypass Prior*: It assumes `server1` is unreachable or hostile and attempts to alter client config to route around `server1` (`set_proxy_jump(server2, jump=server3)`), breaking network isolation.
- **`gemini-4-argon` (Daemon Log Dependence)**:
  - Gemini Argon (budget: 1024 thinking tokens) consistently executes `inspect_server(server, view="logs")` targeting the server alias parsed from the initial stderr trace.
  - Because OpenSSH `sshd` logs `Authentication refused: bad ownership or modes for file /home/deploy/.ssh/authorized_keys`, Gemini reads the exact natural-language diagnosis directly from the daemon log.
  - Even when `view="logs"` is removed from the tool inventory, Gemini's thinking trace prompts it to check `auth_file_metadata` rather than client options, discovering mode `0666`.

### 3. Joint High-Failure Regime: The Cascaded Decoy Trap
- When a 3-node chain features a transit failure on Hop 1 (`AllowTcpForwarding no`) and a secondary flaw on Hop 2 (`authorized_keys 0666`), **BOTH Gemini 4 Argon and GPT-6 Luna exhibit 100% failure rates**.
- Under single-action operational constraints, both models exhaust their single allowed repair on the first detected flaw, leaving the second flaw intact and the target host inaccessible.

---

## 5. Formal Causal Invariants

$$\begin{aligned}
\text{Dominance}(h_1, h_2) &\iff \forall \pi \in \text{Paths}(\text{client}, h_2), \; h_1 \in \pi \\
\text{TransitReject}(h_1) &\implies \text{ObservableState}(h_2) = \bot
\end{aligned}$$

1. **The StrictModes Invariant**: An OpenSSH server enforcing `StrictModes yes` emits the exact same surface symptom (`Permission denied (publickey)`) whether the key is missing or the file is world-writable (`0666`). An agent must verify POSIX file modes before attempting key appending.
2. **The Causal Horizon Rule**: In a cascaded jump chain $h_0 \to h_1 \to \dots \to h_k$, failure on $h_i$ masks all downstream configuration states $h_{i+1} \dots h_k$.
3. **The Anti-Bypass Topological Invariant**: In an isolated subnet topology, reconfiguring `ProxyJump` to bypass an intermediate transit host violates network reachability invariants and guarantees a connection timeout.

---

## 6. Reproduction Script

Run the automated evaluation suite from the multi-hop lab environment:

```bash
cd /home/agent1/testsshprobs/lab/multihop
python3 ssh_eval_suite.py
```

Results are saved to `minimal_high_failure_benchmark_results.json` with full API request/response traces, token latencies, and tool execution history.
