#!/usr/bin/env python3
"""
test_maxsessions_zero.py

Instance 19: MaxSessions 0 Session Denial vs Direct-TCPIP Channel Aliasing
Topology:
  8-server cascade to mh-server-8.

Root Cause:
  mh-server-8 has MaxSessions 0 in /etc/ssh/sshd_config.
  Public key authentication succeeds, but session channel request is rejected.

Observable Error:
  channel 0: open failed: administratively prohibited: open failed

Cognitive Trap:
  The error string 'administratively prohibited' is identical to TCP port forwarding refusal.
  Fast LLMs overwhelmingly assume an intermediate jump host has 'AllowTcpForwarding no',
  mutating intermediate jump hosts (server7, server6) or blaming forwarding.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from ssh_eval_suite import (
    ToolDefinition,
    GeminiArgonAgent,
    ToolExecutionRecord,
    LabDispatcher,
)

def setup_maxsessions_zero(lab_dir: Path) -> None:
    # 1. Reset baseline
    subprocess.run([str(lab_dir / "start.sh")], cwd=lab_dir, stdout=subprocess.DEVNULL, check=True)
    
    # 2. Inject MaxSessions 0 on mh-server-8
    subprocess.run(
        ["sudo", "docker", "exec", "--user", "root", "mh-server-8", "sh", "-c", 
         "printf '\\nMaxSessions 0\\n' >> /etc/ssh/sshd_config && kill -HUP 1"],
        check=True
    )
    print("Instance 19 successfully setup: mh-server-8 has MaxSessions 0.")

def main() -> None:
    lab_dir = Path("/home/agent1/testsshprobs/lab/multihop")
    gk = (lab_dir / "gemini.key.txt").read_text().strip()
    setup_maxsessions_zero(lab_dir)

    dispatcher = LabDispatcher(lab_dir)
    orig_dispatch = dispatcher.dispatch

    allowed = ["server1", "server2", "server3", "server4", "server5", "server6", "server7", "server8"]

    tools = [
        ToolDefinition(
            name="connect",
            description="Attempt a remote hostname check from client to server8. Returns exit_code, stdout, stderr.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": ["server8"]},
                    "verbose": {"type": "boolean"},
                },
                "required": ["target", "verbose"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="inspect_server",
            description="Read-only view of server configuration, logs, or status.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": allowed},
                    "view": {"type": "string", "enum": ["logs", "auth_file_metadata", "sshd_config", "status"]},
                },
                "required": ["server", "view"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="change_sshd_directive",
            description="Update an OpenSSH daemon directive (e.g. MaxSessions, AllowTcpForwarding) and reload sshd.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": allowed},
                    "directive": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["server", "directive", "value"],
                "additionalProperties": False,
            },
        ),
    ]

    prompt = (
        "Diagnose and fix the SSH connection failure from client to server8. "
        "First call connect(target='server8', verbose=True) to observe the failure. "
        "Identify the root cause, apply the minimal fix, and verify with connect."
    )

    agent = GeminiArgonAgent(gk, model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), thinking_budget=1024)
    history: list[dict[str, Any]] = [{"role": "user", "parts": [{"text": prompt}]}]
    actions_taken: list[str] = []

    print("\nStarting multi-turn agent evaluation on Instance 19 (MaxSessions 0 vs Forwarding)...")
    for turn in range(6):
        resp, tool_calls, lat = agent.run_turn(history, tools)
        cand = resp.get("candidates", [{}])[0]
        model_content = cand.get("content", {})
        history.append(model_content)

        if not tool_calls:
            print(f"[Turn {turn}] Agent concluded turns.")
            break

        user_parts: list[dict[str, Any]] = []
        for fn_name, fn_args in tool_calls:
            print(f"  [Turn {turn}] Tool Call: {fn_name}({fn_args})")
            if fn_name == "change_sshd_directive":
                actions_taken.append(f"{fn_name}({json.dumps(fn_args)})")
            res = dispatcher.dispatch(fn_name, fn_args, allowed)
            trunc_res = str(res)[:120]
            print(f"         Result: {trunc_res}")
            user_parts.append({"functionResponse": {"name": fn_name, "response": res}})
        history.append({"role": "user", "parts": user_parts})

    print("\n--------------------------------------------------------------------------------")
    print("EXPERIMENT EVALUATION:")
    print("--------------------------------------------------------------------------------")
    print(f"Actions taken: {actions_taken}")
    
    fixed_maxsessions = any("MaxSessions" in a and "server8" in a for a in actions_taken)
    mutated_forwarding = any("AllowTcpForwarding" in a for a in actions_taken)
    mutated_intermediate = any("server8" not in a for a in actions_taken)

    if mutated_intermediate:
        print(">> VERDICT: [WRONG_HOP_MUTATION] Model mutated intermediate jump hosts due to channel open aliasing!")
    elif mutated_forwarding and not fixed_maxsessions:
        print(">> VERDICT: [ALIASED_FORWARDING_BLINDNESS] Model blamed AllowTcpForwarding instead of MaxSessions!")
    elif fixed_maxsessions:
        print(">> VERDICT: [SUCCESS_ROOT_CAUSE_ISOLATED] Model correctly identified MaxSessions 0 on server8!")
    else:
        print(f">> VERDICT: [UNKNOWN_FAILURE] actions: {actions_taken}")

if __name__ == "__main__":
    main()
