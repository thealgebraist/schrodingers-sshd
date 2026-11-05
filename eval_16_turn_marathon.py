#!/usr/bin/env python3
"""
eval_16_turn_marathon.py

16-Turn SSH Autonomous Diagnosis Marathon Benchmark:
Evaluates whether fast-reasoning agents (GPT-6 Luna Low & Gemini 4 Argon Low)
can escape cognitive attractors and solve complex or baited SSH problems
when granted up to 16 interactive turns (instead of single-turn constraints).

Models Tested:
  - OpenAI GPT-6 Luna Low (reasoning effort: low, Responses API)
  - Google Gemini 4 Argon Low (thinking budget: 1024, Generative Language API)

Target Scenarios:
1. shadow-bait-16turn (Scale 3):
   AuthorizedKeysFile /etc/ssh/keys/%u (invalid key); bait ~/.ssh/authorized_keys 0666 (valid key).
2. parent-perm-trap-16turn (Scale 2):
   /home/deploy mode 0777; .ssh is 0700; authorized_keys is 0600.
3. wildcard-loop-16turn (Scale 3):
   Host * ProxyJump server3 at line 1 shadows all host stanzas.

Strict typing: PEP 484 / PEP 526 / PEP 585 / PEP 604.
"""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Final, Literal

from ssh_eval_suite import (
    ExperimentOrchestrator,
    ToolDefinition,
    GeminiArgonAgent,
    OpenAILunaAgent,
    build_tool_inventory,
    ToolExecutionRecord,
    LabDispatcher,
)

ScenarioName = Literal[
    "shadow-bait-16turn",
    "parent-perm-trap-16turn",
    "wildcard-loop-16turn",
    "compound-cascade-16turn",
]

AgentModelName = Literal["openai_luna", "gemini_argon"]

@dataclasses.dataclass
class MarathonTurnRecord:
    turn_index: int
    tool_calls: list[tuple[str, dict[str, Any]]]
    tool_outputs: list[dict[str, Any]]
    thinking_snippet: str
    target_verified_after_turn: bool
    turn_latency_seconds: float

@dataclasses.dataclass
class MarathonTrialResult:
    trial_id: str
    model: AgentModelName
    scenario: ScenarioName
    max_turns_allowed: int
    turns_used: int
    task_success: bool
    final_verification_exit_code: int
    final_verification_stdout: str
    turn_records: list[MarathonTurnRecord]
    observed_loop_pattern: str | None
    total_duration_seconds: float

class MarathonEvaluator:
    def __init__(self, lab_dir: Path, openai_key: str, gemini_key: str) -> None:
        self.lab_dir: Final[Path] = lab_dir
        self.orchestrator: Final[ExperimentOrchestrator] = ExperimentOrchestrator(lab_dir, openai_key, gemini_key)
        self.dispatcher: Final[LabDispatcher] = self.orchestrator.dispatcher
        self.openai_key: Final[str] = openai_key
        self.gemini_key: Final[str] = gemini_key

    def reset_baseline(self) -> None:
        """Restores client config and server configs to clean 8-hop baseline."""
        cfg_backup = self.lab_dir / "backups" / "client_config_8hop_baseline"
        cfg_client = self.lab_dir / "client" / ".ssh" / "config"
        cfg_client.write_text(cfg_backup.read_text(encoding="utf-8"), encoding="utf-8")

        servers = ["server1", "server2", "server3", "server4", "server5", "server6", "server7", "server8"]
        for s in servers:
            cname = f"mh-server-{s.removeprefix('server')}"
            subprocess.run(["sudo", "docker", "exec", "--user", "root", cname, "chmod", "0755", "/home/deploy"], check=True)
            subprocess.run(["sudo", "docker", "exec", "--user", "root", cname, "chmod", "0700", "/home/deploy/.ssh"], check=True)
            subprocess.run(["sudo", "docker", "exec", "--user", "root", cname, "chmod", "0600", "/home/deploy/.ssh/authorized_keys"], check=True)
            clean_cmd = (
                "sed -i '/AuthorizedKeysFile/d; /Match User/,$d; /PermitOpen/d; /AllowTcpForwarding/d; /ForceCommand/d' /etc/ssh/sshd_config && "
                "echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config && "
                "kill -HUP 1"
            )
            subprocess.run(["sudo", "docker", "exec", "--user", "root", cname, "sh", "-c", clean_cmd], check=True)
            # Remove custom key directories if any
            subprocess.run(["sudo", "docker", "exec", "--user", "root", cname, "rm", "-rf", "/etc/ssh/keys"], check=True)

    def setup_scenario(self, scenario: ScenarioName) -> tuple[str, list[str], list[str], list[str]]:
        self.reset_baseline()

        if scenario == "shadow-bait-16turn":
            # Scale 3: client -> server1 -> server2. Target: server2.
            # On server1: AuthorizedKeysFile points to /etc/ssh/keys/%u with dummy key.
            # Decoy: /home/deploy/.ssh/authorized_keys is 0666 with real key.
            subprocess.run(["sudo", "docker", "exec", "mh-server-1", "mkdir", "-p", "/etc/ssh/keys"], check=True)
            subprocess.run(["sudo", "docker", "exec", "mh-server-1", "chmod", "0755", "/etc/ssh/keys"], check=True)
            subprocess.run(
                ["sudo", "docker", "exec", "-i", "--user", "root", "mh-server-1", "sh", "-c",
                 "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummyKeyForBait1234567890 deploy@bait' > /etc/ssh/keys/deploy"],
                check=True
            )
            subprocess.run(["sudo", "docker", "exec", "mh-server-1", "chmod", "0644", "/etc/ssh/keys/deploy"], check=True)
            clean_cmd = (
                "sed -i '/AuthorizedKeysFile/d' /etc/ssh/sshd_config && "
                "echo 'AuthorizedKeysFile /etc/ssh/keys/%u' >> /etc/ssh/sshd_config && "
                "kill -HUP 1"
            )
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "sh", "-c", clean_cmd], check=True)
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0666", "/home/deploy/.ssh/authorized_keys"], check=True)

            target_host = "server2"
            allowed_servers = ["server1", "server2", "server3"]
            jump_targets = ["server2", "server3"]
            jump_hosts = ["server1", "server2", "server3"]
            return target_host, allowed_servers, jump_targets, jump_hosts

        elif scenario == "parent-perm-trap-16turn":
            # Scale 2: client -> server1. Target: server1.
            # /home/deploy is 0777. Inner files are 0700 and 0600.
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0777", "/home/deploy"], check=True)
            target_host = "server1"
            allowed_servers = ["server1"]
            jump_targets = []
            jump_hosts = []
            return target_host, allowed_servers, jump_targets, jump_hosts

        elif scenario == "wildcard-loop-16turn":
            # Scale 3: client -> server1 -> server2. Target: server2.
            # ProxyJump server3 under Host * in client config.
            cfg_path = self.lab_dir / "client" / ".ssh" / "config"
            cfg = cfg_path.read_text(encoding="utf-8")
            lines = cfg.splitlines()
            s1_idx = next(i for i, l in enumerate(lines) if l.strip().startswith("Host server1"))
            lines.insert(s1_idx - 1, "    ProxyJump server3")
            cfg_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            target_host = "server2"
            allowed_servers = ["server1", "server2", "server3"]
            jump_targets = ["server2", "server3"]
            jump_hosts = ["server1", "server2", "server3"]
            return target_host, allowed_servers, jump_targets, jump_hosts

        elif scenario == "compound-cascade-16turn":
            # Scale 4: client -> server1 -> server3 -> server2. Target: server2.
            # Fault 1: server1 has AllowTcpForwarding no
            # Fault 2: server3 has PermitOpen 10.201.32.2:22 (IP literal mismatch vs hostname)
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "sh", "-c",
                            "sed -i '/AllowTcpForwarding/d' /etc/ssh/sshd_config && echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config && kill -HUP 1"], check=True)
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-3", "sh", "-c",
                            "echo 'PermitOpen 10.201.32.2:22' >> /etc/ssh/sshd_config && kill -HUP 1"], check=True)

            target_host = "server2"
            allowed_servers = ["server1", "server2", "server3"]
            jump_targets = ["server2", "server3"]
            jump_hosts = ["server1", "server2", "server3"]
            return target_host, allowed_servers, jump_targets, jump_hosts

        raise ValueError(f"Unknown scenario: {scenario}")

    def run_marathon(
        self,
        scenario: ScenarioName,
        agent_type: AgentModelName,
        max_turns: int = 16,
    ) -> MarathonTrialResult:
        target_host, allowed_servers, jump_targets, jump_hosts = self.setup_scenario(scenario)
        tools = build_tool_inventory(allowed_servers, jump_targets, jump_hosts)

        prompt = (
            f"Use SSH from this client to run hostname on {target_host}. "
            f"If it fails, you are allowed up to {max_turns} interactive turns to diagnose and fix the SSH connection. "
            f"In each turn, you may inspect client or server state, apply a reversible fix, and test connectivity. "
            f"Allowed target servers for this cluster: {allowed_servers}. "
            f"Stop when hostname on {target_host} succeeds."
        )

        turn_records: list[MarathonTurnRecord] = []
        start_time = time.time()
        turns_used = 0
        task_success = False

        if agent_type == "openai_luna":
            luna_agent = OpenAILunaAgent(self.openai_key, model="gpt-6-luna", effort="low")
            history: list[dict[str, Any]] = [{"role": "user", "content": [{"type": "input_text", "text": prompt}]}]

            for turn in range(max_turns):
                turns_used = turn + 1
                turn_resp, tool_calls, lat = luna_agent.run_turn(history, tools)

                thinking_snip = ""
                for item in turn_resp.get("output", []):
                    if item.get("type") == "reasoning":
                        thinking_snip += str(item.get("summary", "")) or str(item.get("content", ""))

                if not tool_calls:
                    # Model stopped calling tools
                    break

                history.extend(turn_resp.get("output", []))
                executed_calls: list[tuple[str, dict[str, Any]]] = []
                executed_outputs: list[dict[str, Any]] = []

                for fn_name, fn_args, call_id in tool_calls:
                    executed_calls.append((fn_name, fn_args))
                    res = self.dispatcher.dispatch(fn_name, fn_args, allowed_servers)
                    executed_outputs.append(res)
                    history.append({"type": "function_call_output", "call_id": call_id, "output": json.dumps(res)})

                # Check if target is verified after this turn
                v_res = self.dispatcher.verify_target(target_host)
                is_ok = (v_res["exit_code"] == 0 and target_host in v_res["stdout"])
                turn_records.append(MarathonTurnRecord(
                    turn_index=turn,
                    tool_calls=executed_calls,
                    tool_outputs=executed_outputs,
                    thinking_snippet=thinking_snip[:200],
                    target_verified_after_turn=is_ok,
                    turn_latency_seconds=lat,
                ))

                if is_ok:
                    task_success = True
                    break

        elif agent_type == "gemini_argon":
            gemini_agent = GeminiArgonAgent(self.gemini_key, model="gemini-4-argon", thinking_budget=1024)
            gemini_history: list[dict[str, Any]] = [{"role": "user", "parts": [{"text": prompt}]}]

            for turn in range(max_turns):
                turns_used = turn + 1
                turn_resp, tool_calls_gemini, lat = gemini_agent.run_turn(gemini_history, tools)

                thinking_snip = ""
                cand = turn_resp.get("candidates", [{}])[0]
                model_content = cand.get("content", {})
                gemini_history.append(model_content)

                for part in model_content.get("parts", []):
                    if "thought" in part:
                        thinking_snip += part["thought"]

                if not tool_calls_gemini:
                    break

                user_parts: list[dict[str, Any]] = []
                executed_calls_g: list[tuple[str, dict[str, Any]]] = []
                executed_outputs_g: list[dict[str, Any]] = []

                for fn_name, fn_args in tool_calls_gemini:
                    executed_calls_g.append((fn_name, fn_args))
                    res = self.dispatcher.dispatch(fn_name, fn_args, allowed_servers)
                    executed_outputs_g.append(res)
                    user_parts.append({"functionResponse": {"name": fn_name, "response": res}})

                gemini_history.append({"role": "user", "parts": user_parts})

                v_res = self.dispatcher.verify_target(target_host)
                is_ok = (v_res["exit_code"] == 0 and target_host in v_res["stdout"])
                turn_records.append(MarathonTurnRecord(
                    turn_index=turn,
                    tool_calls=executed_calls_g,
                    tool_outputs=executed_outputs_g,
                    thinking_snippet=thinking_snip[:200],
                    target_verified_after_turn=is_ok,
                    turn_latency_seconds=lat,
                ))

                if is_ok:
                    task_success = True
                    break

        # Final verification check
        final_v = self.dispatcher.verify_target(target_host)
        final_success = (final_v["exit_code"] == 0 and target_host in final_v["stdout"])
        duration = round(time.time() - start_time, 2)

        # Detect loop patterns
        loop_pattern = None
        action_seq = [tc[0] for rec in turn_records for tc in rec.tool_calls]
        if len(action_seq) >= 4 and len(set(action_seq)) <= 2:
            loop_pattern = f"CYCLIC_OSCILLATION_{set(action_seq)}"
        elif turns_used >= max_turns and not final_success:
            loop_pattern = "BUDGET_EXHAUSTION_WITHOUT_CONVERGENCE"

        return MarathonTrialResult(
            trial_id=f"marathon_{int(time.time())}",
            model=agent_type,
            scenario=scenario,
            max_turns_allowed=max_turns,
            turns_used=turns_used,
            task_success=final_success,
            final_verification_exit_code=final_v["exit_code"],
            final_verification_stdout=final_v["stdout"],
            turn_records=turn_records,
            observed_loop_pattern=loop_pattern,
            total_duration_seconds=duration,
        )

def main() -> None:
    lab_dir = Path("/home/agent1/testsshprobs/lab/multihop")
    ok = (lab_dir / "openai.key.txt").read_text().strip()
    gk = (lab_dir / "gemini.key.txt").read_text().strip()

    evaluator = MarathonEvaluator(lab_dir, ok, gk)
    scenarios: list[ScenarioName] = [
        "shadow-bait-16turn",
        "parent-perm-trap-16turn",
        "wildcard-loop-16turn",
    ]
    models: list[AgentModelName] = ["openai_luna", "gemini_argon"]

    print("================================================================================")
    print("16-TURN SSH AUTONOMOUS MARATHON: TESTING PERSISTENT FAILURE UNDER EXTENDED TRIES")
    print("================================================================================")

    all_results = []
    for sc in scenarios:
        print(f"\n>>> SCENARIO: {sc}")
        for md in models:
            print(f"  [{md:12}] Running up to 16 turns ... ", end="", flush=True)
            res = evaluator.run_marathon(sc, md, max_turns=16)
            status = "SUCCESS" if res.task_success else "FAILED (16-TURN EXHAUSTION)"
            print(f"[{status}] Turns: {res.turns_used}/16 | Loop: {res.observed_loop_pattern} | Duration: {res.total_duration_seconds}s")
            all_results.append(dataclasses.asdict(res))

    out_file = lab_dir / "marathon_16turn_results.json"
    out_file.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    print(f"\n[DONE] Marathon results saved to {out_file}")

if __name__ == "__main__":
    main()
