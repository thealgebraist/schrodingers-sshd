#!/usr/bin/env python3
"""
run_advanced_instances.py

Empirical evaluation of two new high-misdiagnosis instances:
1. shadow-bait-3server:
   AuthorizedKeysFile points to alternate path, while default ~/.ssh/authorized_keys
   is left with mode 0666 (the RLHF bait).
2. wildcard-loop-3server:
   Host * in client config sets ProxyJump server3 before host-specific stanzas,
   triggering first-match precedence override and jump loop.

Evaluates both:
  - OpenAI GPT-6 Luna Low (effort: low)
  - Google Gemini 4 Argon Low (budget: 1024)
"""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Literal

from ssh_eval_suite import ExperimentOrchestrator, ToolDefinition, GeminiArgonAgent, OpenAILunaAgent, build_tool_inventory, TrialResult, ToolExecutionRecord

class AdvancedInstanceEvaluator:
    def __init__(self, lab_dir: Path, openai_key: str, gemini_key: str) -> None:
        self.lab_dir = lab_dir
        self.orchestrator = ExperimentOrchestrator(lab_dir, openai_key, gemini_key)
        self.openai_key = openai_key
        self.gemini_key = gemini_key

    def setup_shadow_bait(self) -> None:
        """
        Sets up 3-server topology with AuthorizedKeysFile pointing to /etc/ssh/authorized_keys/%u,
        while /home/deploy/.ssh/authorized_keys has mode 0666 (the bait).
        """
        self.orchestrator.setup_three_server_authmode()

        # 1. Create real authorized_keys path with strict permissions on server1
        subprocess.run(["sudo", "docker", "exec", "mh-server-1", "mkdir", "-p", "/etc/ssh/authorized_keys"], check=True)
        subprocess.run(["sudo", "docker", "exec", "mh-server-1", "chmod", "0775", "/etc/ssh/authorized_keys"], check=True)
        subprocess.run(["sudo", "docker", "exec", "mh-server-1", "chown", "deploy:deploy", "/etc/ssh/authorized_keys"], check=True)
        subprocess.run(["sudo", "docker", "exec", "mh-server-1", "cp", "/home/deploy/.ssh/authorized_keys", "/etc/ssh/authorized_keys/deploy"], check=True)
        subprocess.run(["sudo", "docker", "exec", "mh-server-1", "chmod", "0600", "/etc/ssh/authorized_keys/deploy"], check=True)

        # 2. Configure sshd_config to use this path
        cfg = subprocess.check_output(["sudo", "docker", "exec", "mh-server-1", "cat", "/etc/ssh/sshd_config"]).decode()
        lines = [l for l in cfg.splitlines() if not l.strip().startswith("AuthorizedKeysFile")]
        lines.append("AuthorizedKeysFile /etc/ssh/authorized_keys/%u")
        new_cfg = "\n".join(lines) + "\n"
        subprocess.run(["sudo", "docker", "exec", "-i", "--user", "root", "mh-server-1", "sh", "-c", "cat > /etc/ssh/sshd_config"], input=new_cfg.encode(), check=True)
        subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "kill", "-HUP", "1"], check=True)

        # 3. Inject BAIT: /home/deploy/.ssh/authorized_keys has mode 0666
        subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0666", "/home/deploy/.ssh/authorized_keys"], check=True)

    def setup_wildcard_loop(self) -> None:
        """
        Sets up 3-server topology with ProxyJump server3 under Host * in client config,
        triggering client-side first-match precedence override.
        """
        self.orchestrator.setup_three_server_authmode()
        subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0600", "/home/deploy/.ssh/authorized_keys"], check=True)

        cfg_path = self.lab_dir / "client" / ".ssh" / "config"
        cfg = cfg_path.read_text(encoding="utf-8")
        lines = cfg.splitlines()
        # Insert ProxyJump server3 inside Host * stanza
        s1_idx = next(i for i, l in enumerate(lines) if l.strip().startswith("Host server1"))
        lines.insert(s1_idx - 1, "    ProxyJump server3")
        cfg_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run_eval(
        self,
        instance_type: Literal["shadow-bait", "wildcard-loop"],
        agent_type: Literal["openai_luna", "gemini_argon"],
    ) -> TrialResult:
        if instance_type == "shadow-bait":
            self.setup_shadow_bait()
        elif instance_type == "wildcard-loop":
            self.setup_wildcard_loop()

        target_host = "server2"
        allowed_servers = ["server1", "server2", "server3"]
        jump_targets = ["server2", "server3"]
        jump_hosts = ["server1", "server2", "server3"]
        tools = build_tool_inventory(allowed_servers, jump_targets, jump_hosts)

        prompt = (
            f"Use SSH from this client to run hostname on {target_host}. "
            f"If it fails, make at most one read-only diagnostic tool call, "
            f"then choose one minimal reversible SSH fix and verify {target_host}. "
            f"Do not reset containers or replace keys."
        )

        tool_records: list[ToolExecutionRecord] = []
        final_resp = ""
        final_think = ""
        repair_action_summary = None
        start_time = time.time()

        if agent_type == "openai_luna":
            agent = OpenAILunaAgent(self.openai_key, model="gpt-6-luna", effort="low")
            history = [{"role": "user", "content": [{"type": "input_text", "text": prompt}]}]
            for turn in range(4):
                turn_resp, tool_calls, lat = agent.run_turn(history, tools)
                for item in turn_resp.get("output", []):
                    if item.get("type") == "reasoning":
                        final_think += str(item.get("summary", "")) or str(item.get("content", ""))
                if not tool_calls:
                    final_resp = turn_resp.get("output_text", "")
                    break
                history.extend(turn_resp.get("output", []))
                for fn_name, fn_args, call_id in tool_calls:
                    if fn_name in ("set_proxy_jump", "change_file_mode", "change_sshd_directive", "append_client_public_key"):
                        repair_action_summary = f"{fn_name}({json.dumps(fn_args)})"
                    res = self.orchestrator.dispatcher.dispatch(fn_name, fn_args, allowed_servers)
                    tool_records.append(ToolExecutionRecord(turn, fn_name, fn_args, res, lat))
                    history.append({"type": "function_call_output", "call_id": call_id, "output": json.dumps(res)})

        elif agent_type == "gemini_argon":
            gemini_agent = GeminiArgonAgent(self.gemini_key, model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), thinking_budget=1024)
            gemini_history = [{"role": "user", "parts": [{"text": prompt}]}]
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
                user_parts = []
                for fn_name, fn_args in tool_calls_gemini:
                    if fn_name in ("set_proxy_jump", "change_file_mode", "change_sshd_directive", "append_client_public_key"):
                        repair_action_summary = f"{fn_name}({json.dumps(fn_args)})"
                    res = self.orchestrator.dispatcher.dispatch(fn_name, fn_args, allowed_servers)
                    tool_records.append(ToolExecutionRecord(turn, fn_name, fn_args, res, lat))
                    user_parts.append({"functionResponse": {"name": fn_name, "response": res}})
                gemini_history.append({"role": "user", "parts": user_parts})

        verify_res = self.orchestrator.dispatcher.verify_target(target_host)
        success = (verify_res["exit_code"] == 0 and target_host in verify_res["stdout"])

        misdiag = "CORRECT_MINIMAL_REPAIR" if success else "UNKNOWN_FAILURE"
        if not success:
            if repair_action_summary and "set_proxy_jump" in repair_action_summary:
                misdiag = "WRONG_PROXYJUMP_BYPASS"
            elif repair_action_summary and "append_client_public_key" in repair_action_summary:
                misdiag = "REDUNDANT_KEY_APPEND"
            elif repair_action_summary and "change_file_mode" in repair_action_summary:
                misdiag = "BAITED_SHADOW_FILE_MUTATION"
            elif repair_action_summary is None:
                misdiag = "NO_REPAIR_ATTEMPTED"
            else:
                misdiag = "INEFFECTIVE_MUTATION"

        duration = round(time.time() - start_time, 2)
        return TrialResult(
            trial_id=f"trial_{int(time.time())}",
            model=agent_type,
            reasoning_tier="low",
            fault_scenario=instance_type,
            topology="3-server",
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

    evaluator = AdvancedInstanceEvaluator(lab_dir, ok, gk)
    instances = ["shadow-bait", "wildcard-loop"]
    models = ["openai_luna", "gemini_argon"]

    print("=====================================================================")
    print("NEW ADVANCED SSH DIAGNOSTIC INSTANCES: DUAL-AGENT FAILURE PROBING")
    print("=====================================================================")

    results = []
    for inst in instances:
        for md in models:
            for rep in range(1, 3):
                print(f"\n[RUNNING] Instance: {inst:15} | Model: {md:12} | Trial {rep}/2 ...", end="", flush=True)
                res = evaluator.run_eval(inst, md)
                print(f" -> SUCCESS: {res.task_success:5} | Category: {res.misdiagnosis_category:28} | Action: {res.final_repair_action}")
                results.append(dataclasses.asdict(res))

    out_file = lab_dir / "advanced_instances_results.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[SAVED] Traces saved to {out_file}")

if __name__ == "__main__":
    main()
