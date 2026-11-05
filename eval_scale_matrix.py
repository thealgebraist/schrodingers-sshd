#!/usr/bin/env python3
"""
eval_scale_matrix.py

Scale-Topological SSH Diagnosis Benchmark across 2, 4, 5, 6, 8 Servers:
Probing Multi-Hop Failure Modes and Cognitive Misdiagnoses in Fast LLM Reasoners:
  - OpenAI GPT-6 Luna Low (reasoning effort: low)
  - Google Gemini 4 Argon Low (thinking budget: 1024)

Scenarios Evaluated:
1. parent-perm-2server (2 servers):
   Target: server1. Root cause: /home/deploy mode 0777 (world-writable).
   Decoy: .ssh is 0700, authorized_keys is 0600. StrictModes failure.
2. match-user-forwarding-4server (4 servers):
   Target: server2 via server3. Root cause: server3 has Match User deploy -> AllowTcpForwarding no
   at bottom of sshd_config while global AllowTcpForwarding is yes.
3. permitopen-ip-hostname-5server (5 servers):
   Target: server4 via server2. Root cause: server2 sshd_config has PermitOpen 10.201.24.4:22.
   Client requests server4:22; OpenSSH literal string comparison rejects forwarding.
4. deep-cascade-transit-6server (6 servers):
   Target: server5 via server4. Root cause: server4 has AllowTcpForwarding no.
   350+ line trace causes context dilution and spatial bypass hallucinations.
5. extreme-cascade-dilution-8server (8 servers):
   Target: server8 via server6. Root cause: server6 has AllowTcpForwarding no.
   550+ line trace causes massive context dilution across 8 hops.

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
    TrialResult,
    ToolExecutionRecord,
    LabDispatcher,
)

ScenarioName = Literal[
    "parent-perm-2server",
    "match-user-forwarding-4server",
    "permitopen-ip-hostname-5server",
    "deep-cascade-transit-6server",
    "extreme-cascade-dilution-8server",
]

AgentModelName = Literal["openai_luna", "gemini_argon"]

@dataclasses.dataclass(frozen=True)
class ScenarioConfig:
    name: ScenarioName
    topology_label: str
    target_host: str
    server_count: int
    allowed_servers: list[str]
    jump_targets: list[str]
    jump_hosts: list[str]
    expected_fault_type: str

SCENARIO_CONFIGS: Final[dict[ScenarioName, ScenarioConfig]] = {
    "parent-perm-2server": ScenarioConfig(
        name="parent-perm-2server",
        topology_label="2-server",
        target_host="server1",
        server_count=2,
        allowed_servers=["server1"],
        jump_targets=[],
        jump_hosts=[],
        expected_fault_type="PARENT_DIR_STRICTMODES_TRAP",
    ),
    "match-user-forwarding-4server": ScenarioConfig(
        name="match-user-forwarding-4server",
        topology_label="4-server",
        target_host="server2",
        server_count=4,
        allowed_servers=["server1", "server3", "server2"],
        jump_targets=["server2", "server3"],
        jump_hosts=["server1", "server3", "server2"],
        expected_fault_type="SCOPED_MATCH_USER_FORWARDING_BLOCK",
    ),
    "permitopen-ip-hostname-5server": ScenarioConfig(
        name="permitopen-ip-hostname-5server",
        topology_label="5-server",
        target_host="server4",
        server_count=5,
        allowed_servers=["server1", "server3", "server2", "server4"],
        jump_targets=["server4", "server2", "server3"],
        jump_hosts=["server1", "server3", "server2", "server4"],
        expected_fault_type="PERMITOPEN_STRING_MISMATCH",
    ),
    "deep-cascade-transit-6server": ScenarioConfig(
        name="deep-cascade-transit-6server",
        topology_label="6-server",
        target_host="server5",
        server_count=6,
        allowed_servers=["server1", "server3", "server2", "server4", "server5"],
        jump_targets=["server5", "server4", "server2", "server3"],
        jump_hosts=["server1", "server3", "server2", "server4", "server5"],
        expected_fault_type="DEEP_INTERMEDIATE_TRANSIT_BLOCKER",
    ),
    "extreme-cascade-dilution-8server": ScenarioConfig(
        name="extreme-cascade-dilution-8server",
        topology_label="8-server",
        target_host="server8",
        server_count=8,
        allowed_servers=["server1", "server3", "server2", "server4", "server5", "server6", "server7", "server8"],
        jump_targets=["server8", "server7", "server6", "server5", "server4", "server2", "server3"],
        jump_hosts=["server1", "server3", "server2", "server4", "server5", "server6", "server7", "server8"],
        expected_fault_type="EXTREME_CASCADE_CONTEXT_DILUTION",
    ),
}

class ScaleMatrixEvaluator:
    def __init__(self, lab_dir: Path, openai_key: str, gemini_key: str) -> None:
        self.lab_dir: Final[Path] = lab_dir
        self.orchestrator: Final[ExperimentOrchestrator] = ExperimentOrchestrator(lab_dir, openai_key, gemini_key)
        self.dispatcher: Final[LabDispatcher] = self.orchestrator.dispatcher
        self.openai_key: Final[str] = openai_key
        self.gemini_key: Final[str] = gemini_key

    def reset_cluster_baseline(self) -> None:
        """Restores client config and all server configs to pristine baseline."""
        cfg_backup = self.lab_dir / "backups" / "client_config_8hop_baseline"
        cfg_client = self.lab_dir / "client" / ".ssh" / "config"
        cfg_client.write_text(cfg_backup.read_text(encoding="utf-8"), encoding="utf-8")

        servers = ["server1", "server2", "server3", "server4", "server5", "server6", "server7", "server8"]
        for s in servers:
            cname = f"mh-server-{s.removeprefix('server')}"
            # Ensure standard permissions
            subprocess.run(["sudo", "docker", "exec", "--user", "root", cname, "chmod", "0755", "/home/deploy"], check=True)
            subprocess.run(["sudo", "docker", "exec", "--user", "root", cname, "chmod", "0700", "/home/deploy/.ssh"], check=True)
            subprocess.run(["sudo", "docker", "exec", "--user", "root", cname, "chmod", "0600", "/home/deploy/.ssh/authorized_keys"], check=True)
            # Clean sshd_config of any Match or PermitOpen or custom AllowTcpForwarding lines
            clean_cmd = (
                "sed -i '/Match User/,$d; /PermitOpen/d; /AllowTcpForwarding/d; /ForceCommand/d' /etc/ssh/sshd_config && "
                "echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config && "
                "kill -HUP 1"
            )
            subprocess.run(["sudo", "docker", "exec", "--user", "root", cname, "sh", "-c", clean_cmd], check=True)

    def setup_scenario(self, scenario: ScenarioName) -> None:
        self.reset_cluster_baseline()

        if scenario == "parent-perm-2server":
            # Target is server1. Home directory chmod 0777 triggers StrictModes refusal.
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0777", "/home/deploy"], check=True)

        elif scenario == "match-user-forwarding-4server":
            # On server3 (intermediate hop), append Match User deploy \n AllowTcpForwarding no
            script = (
                "printf '\nMatch User deploy\n    AllowTcpForwarding no\n' >> /etc/ssh/sshd_config && "
                "kill -HUP 1"
            )
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-3", "sh", "-c", script], check=True)

        elif scenario == "permitopen-ip-hostname-5server":
            # On server2 (intermediate hop to server4), add PermitOpen 10.201.24.4:22
            script = (
                "printf '\nPermitOpen 10.201.24.4:22\n' >> /etc/ssh/sshd_config && "
                "kill -HUP 1"
            )
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-2", "sh", "-c", script], check=True)

        elif scenario == "deep-cascade-transit-6server":
            # On server4 (4th hop in 5-hop chain to server5), set AllowTcpForwarding no
            script = (
                "sed -i '/AllowTcpForwarding/d' /etc/ssh/sshd_config && "
                "echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config && "
                "kill -HUP 1"
            )
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-4", "sh", "-c", script], check=True)

        elif scenario == "extreme-cascade-dilution-8server":
            # On server6 (6th hop in 8-hop chain to server8), set AllowTcpForwarding no
            script = (
                "sed -i '/AllowTcpForwarding/d' /etc/ssh/sshd_config && "
                "echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config && "
                "kill -HUP 1"
            )
            subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-6", "sh", "-c", script], check=True)

    def run_eval(
        self,
        scenario_name: ScenarioName,
        agent_type: AgentModelName,
    ) -> TrialResult:
        cfg = SCENARIO_CONFIGS[scenario_name]
        self.setup_scenario(scenario_name)

        tools = build_tool_inventory(cfg.allowed_servers, cfg.jump_targets, cfg.jump_hosts)
        prompt = (
            f"Use SSH from this client to run hostname on {cfg.target_host}. "
            f"If it fails, make at most one read-only diagnostic tool call, "
            f"then choose one minimal reversible SSH fix and verify with hostname. "
            f"Allowed target servers for this cluster: {cfg.allowed_servers}."
        )

        tool_records: list[ToolExecutionRecord] = []
        repair_action_summary: str | None = None
        final_resp: str = ""
        final_think: str = ""
        start_time: float = time.time()

        if agent_type == "openai_luna":
            luna_agent = OpenAILunaAgent(self.openai_key, model="gpt-6-luna", effort="low")
            history: list[dict[str, Any]] = [{"role": "user", "content": [{"type": "input_text", "text": prompt}]}]
            for turn in range(4):
                turn_resp, tool_calls_luna, lat = luna_agent.run_turn(history, tools)
                for item in turn_resp.get("output", []):
                    if item.get("type") == "reasoning":
                        final_think += str(item.get("summary", "")) or str(item.get("content", ""))
                if not tool_calls_luna:
                    final_resp = turn_resp.get("output_text", "")
                    break
                history.extend(turn_resp.get("output", []))
                for fn_name, fn_args, call_id in tool_calls_luna:
                    if fn_name in ("set_proxy_jump", "change_file_mode", "change_sshd_directive", "append_client_public_key"):
                        repair_action_summary = f"{fn_name}({json.dumps(fn_args)})"
                    res = self.dispatcher.dispatch(fn_name, fn_args, cfg.allowed_servers)
                    tool_records.append(ToolExecutionRecord(turn, fn_name, fn_args, res, lat))
                    history.append({"type": "function_call_output", "call_id": call_id, "output": json.dumps(res)})

        elif agent_type == "gemini_argon":
            gemini_agent = GeminiArgonAgent(self.gemini_key, model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), thinking_budget=1024)
            gemini_history: list[dict[str, Any]] = [{"role": "user", "parts": [{"text": prompt}]}]
            for turn in range(4):
                turn_resp, tool_calls_gemini, lat = gemini_agent.run_turn(gemini_history, tools)
                cand = turn_resp.get("candidates", [{}])[0]
                model_content = cand.get("content", {})
                gemini_history.append(model_content)
                if not tool_calls_gemini:
                    for p in model_content.get("parts", []):
                        if "text" in p:
                            final_resp += p["text"]
                        if "thought" in p:
                            final_think += p["thought"]
                    break
                user_parts: list[dict[str, Any]] = []
                for fn_name, fn_args in tool_calls_gemini:
                    if fn_name in ("set_proxy_jump", "change_file_mode", "change_sshd_directive", "append_client_public_key"):
                        repair_action_summary = f"{fn_name}({json.dumps(fn_args)})"
                    res = self.dispatcher.dispatch(fn_name, fn_args, cfg.allowed_servers)
                    tool_records.append(ToolExecutionRecord(turn, fn_name, fn_args, res, lat))
                    user_parts.append({"functionResponse": {"name": fn_name, "response": res}})
                gemini_history.append({"role": "user", "parts": user_parts})

        verify_res = self.dispatcher.verify_target(cfg.target_host)
        success = (verify_res["exit_code"] == 0 and cfg.target_host in verify_res["stdout"])

        # Cognitive misdiagnosis classification
        misdiag = "CORRECT_MINIMAL_REPAIR" if success else "UNKNOWN_FAILURE"
        if not success:
            if repair_action_summary and "set_proxy_jump" in repair_action_summary:
                misdiag = "SPATIAL_BYPASS_ILLUSION"
            elif repair_action_summary and "append_client_public_key" in repair_action_summary:
                misdiag = "REDUNDANT_KEY_APPEND_PRIOR"
            elif repair_action_summary and "change_file_mode" in repair_action_summary:
                if "/home/deploy/.ssh" in repair_action_summary:
                    misdiag = "WRONG_INNER_FILE_MODE_FIX"
                else:
                    misdiag = "INEFFECTIVE_FILE_MODE_MUTATION"
            elif repair_action_summary and "change_sshd_directive" in repair_action_summary:
                # Target attribution vs transit attribution
                if cfg.target_host in repair_action_summary:
                    misdiag = "TERMINAL_NODE_ATTRIBUTION_ERROR"
                else:
                    misdiag = "WRONG_HOP_DIRECTIVE_MUTATION"
            elif repair_action_summary is None:
                misdiag = "NO_REPAIR_ATTEMPTED"

        duration = round(time.time() - start_time, 2)
        return TrialResult(
            trial_id=f"trial_scale_{int(time.time())}",
            model=agent_type,
            reasoning_tier="low",
            fault_scenario=scenario_name,
            topology=cfg.topology_label,
            initial_exit_code=255,
            initial_stderr="",
            tool_records=tool_records,
            final_response_text=final_resp.strip(),
            final_thinking_text=final_think.strip(),
            final_repair_action=repair_action_summary,
            verification_exit_code=verify_res["exit_code"],
            verification_stdout=verify_res["stdout"],
            task_success=success,
            misdiagnosis_category=misdiag,
            total_duration_seconds=duration,
        )

def main() -> None:
    lab_dir = Path("/home/agent1/testsshprobs/lab/multihop")
    ok = (lab_dir / "openai.key.txt").read_text().strip()
    gk = (lab_dir / "gemini.key.txt").read_text().strip()

    evaluator = ScaleMatrixEvaluator(lab_dir, ok, gk)
    scenarios: list[ScenarioName] = [
        "parent-perm-2server",
        "match-user-forwarding-4server",
        "permitopen-ip-hostname-5server",
        "deep-cascade-transit-6server",
        "extreme-cascade-dilution-8server",
    ]
    models: list[AgentModelName] = ["openai_luna", "gemini_argon"]

    print("================================================================================")
    print("SCALE-TOPOLOGICAL SSH BENCHMARK: DIVERSE FAULT TYPES (2, 4, 5, 6, 8 SERVERS)")
    print("================================================================================")

    all_results: list[dict[str, Any]] = []
    for sc in scenarios:
        cfg = SCENARIO_CONFIGS[sc]
        print(f"\n>>> SCENARIO: {sc} (Topology: {cfg.topology_label}, Target: {cfg.target_host})")
        print(f"    Expected Fault: {cfg.expected_fault_type}")
        for md in models:
            for rep in range(1, 3):
                print(f"  [{md:12} | Trial {rep}/2] Running ... ", end="", flush=True)
                res = evaluator.run_eval(sc, md)
                status = "SUCCESS" if res.task_success else "MISDIAGNOSED"
                print(f"[{status}] Cat: {res.misdiagnosis_category:32} | Action: {res.final_repair_action}")
                all_results.append(dataclasses.asdict(res))

    out_path = lab_dir / "scale_matrix_results.json"
    out_path.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    print(f"\n[DONE] All evaluation trials recorded in {out_path}")

if __name__ == "__main__":
    main()
