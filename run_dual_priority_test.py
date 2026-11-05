#!/usr/bin/env python3
"""
run_dual_priority_test.py

Dual-Fault Priority Ordering Experiment:
Tests whether an LLM (Gemini 3.8 Flash) can correctly identify and order
remediation actions when a catastrophic system fault (100% full /tmp, ENOSPC)
coexists with an SSH configuration fault (StrictModes 0666 authorized_keys).

Causal Ordering Requirement:
  Order 1: clean_temp_storage (restore storage headroom on /tmp)
  Order 2: change_file_mode (correct authorized_keys mode to 0600)
  Order 3: verify SSH connection (run hostname on server1)
"""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from ssh_eval_suite import (
    ExperimentOrchestrator,
    ToolDefinition,
    GeminiArgonAgent,
    build_tool_inventory,
    ToolExecutionRecord,
    LabDispatcher,
)

def setup_dual_fault(lab_dir: Path) -> None:
    """Sets up server1 with 100% full /tmp (ENOSPC) AND mode 0666 authorized_keys."""
    subprocess.run([str(lab_dir / "start.sh")], cwd=lab_dir, stdout=subprocess.DEVNULL, check=True)
    subprocess.run(
        ["sudo", "docker", "stop", "mh-server-2", "mh-server-3", "mh-server-4", "mh-server-5", "mh-server-6", "mh-server-7", "mh-server-8"],
        stdout=subprocess.DEVNULL,
        check=True,
    )
    # 1. Mount 1M tmpfs on /tmp in mh-server-1 and fill it completely
    pid = subprocess.check_output(["sudo", "docker", "inspect", "--format", "{{.State.Pid}}", "mh-server-1"]).decode().strip()
    subprocess.run(["sudo", "nsenter", "-t", pid, "-m", "mount", "-t", "tmpfs", "-o", "size=1M,mode=1777", "tmpfs", "/tmp"], check=True)
    subprocess.run(["sudo", "docker", "exec", "mh-server-1", "sh", "-c", "dd if=/dev/zero of=/tmp/overflow.dump bs=1M count=1 2>/dev/null || true"], check=True)

    # 2. Inject StrictModes fault: mode 0666 on authorized_keys
    subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0666", "/home/deploy/.ssh/authorized_keys"], check=True)
    print("Dual fault successfully injected on server1: /tmp is 100% FULL and authorized_keys is mode 0666.")

def extend_dispatcher(dispatcher: LabDispatcher) -> tuple[LabDispatcher, list[ToolDefinition]]:
    orig_dispatch = dispatcher.dispatch
    def patched_dispatch(name: str, args: dict[str, Any], allowed_servers: list[str]) -> dict[str, Any]:
        if name == "clean_temp_storage":
            server = str(args["server"])
            cname = f"mh-server-{server.removeprefix('server')}"
            res = dispatcher.execute_host_command([
                "sudo", "docker", "exec", "--user", "root", cname, "sh", "-c", "rm -f /tmp/overflow.dump /tmp/*.dump && df -h /tmp"
            ])
            return {"status": "SUCCESS", "server": server, "cleaned": True, "disk_state": res["stdout"]}
        
        if name == "inspect_server" and args.get("view") == "disk_space":
            server = str(args["server"])
            cname = f"mh-server-{server.removeprefix('server')}"
            return dispatcher.execute_host_command(["sudo", "docker", "exec", cname, "df", "-h", "/", "/tmp"])
        
        return orig_dispatch(name, args, allowed_servers)
    dispatcher.dispatch = patched_dispatch

    allowed_servers = ["server1"]
    tools = [
        ToolDefinition(
            name="connect",
            description="Attempt a remote hostname check from the client to server. Returns exit_code, stdout, stderr.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": ["server1"]},
                    "verbose": {"type": "boolean"},
                },
                "required": ["target", "verbose"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="inspect_server",
            description="Read-only view of server sshd_config, disk_space, logs, or file permissions.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1"]},
                    "view": {"type": "string", "enum": ["disk_space", "logs", "auth_file_metadata", "sshd_config", "status"]},
                },
                "required": ["server", "view"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="clean_temp_storage",
            description="Purge overflow dump files on /tmp to free exhausted disk space (fixes ENOSPC / 100% full /tmp).",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1"]},
                },
                "required": ["server"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="change_file_mode",
            description="Change the mode of permitted paths on a server (e.g. authorized_keys to 0600 or 0644).",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1"]},
                    "path": {"type": "string", "enum": ["/home/deploy", "/home/deploy/.ssh", "/home/deploy/.ssh/authorized_keys"]},
                    "mode": {"type": "string", "enum": ["0755", "0700", "0600", "0644"]},
                },
                "required": ["server", "path", "mode"],
                "additionalProperties": False,
            },
        ),
    ]
    return dispatcher, tools

def main() -> None:
    lab_dir = Path("/home/agent1/testsshprobs/lab/multihop")
    gk = (lab_dir / "gemini.key.txt").read_text().strip()
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

    print("================================================================================")
    print(" DUAL-FAULT PRIORITY ORDERING BENCHMARK: ENOSPC /tmp + STRICTMODES SSH")
    print(f" Target Model: {model_name} (Google Generative AI)")
    print("================================================================================")

    setup_dual_fault(lab_dir)
    dispatcher = LabDispatcher(lab_dir)
    dispatcher, tools = extend_dispatcher(dispatcher)

    prompt = (
        "You are repairing a production server ('server1'). "
        "A critical alert reported: 'SSH access to server1 failed, and system monitoring shows severe resource pressure'. "
        "Use SSH to run hostname on server1. If it fails, inspect server diagnostics (logs, disk space, auth metadata). "
        "IMPORTANT: If there are multiple problems (e.g. storage exhaustion vs configuration permissions), "
        "you MUST resolve them in the sound, safe priority order (critical system invariants first, then service configuration). "
        "After applying fixes, verify server1."
    )

    agent = GeminiArgonAgent(gk, model=model_name, thinking_budget=1024)
    history: list[dict[str, Any]] = [{"role": "user", "parts": [{"text": prompt}]}]
    
    actions_ordered: list[str] = []
    tool_records: list[ToolExecutionRecord] = []

    for turn in range(6):
        turn_resp, tool_calls, lat = agent.run_turn(history, tools)
        cand = turn_resp.get("candidates", [{}])[0]
        model_content = cand.get("content", {})
        history.append(model_content)

        if not tool_calls:
            print(f"\n[Turn {turn}] Agent concluded turns with explanation.")
            for p in model_content.get("parts", []):
                if "text" in p:
                    print(f"Agent Final Text:\n{p['text']}")
            break

        user_parts = []
        for fn_name, fn_args in tool_calls:
            print(f"  [Turn {turn}] Tool Call: {fn_name}({fn_args})")
            if fn_name in ("clean_temp_storage", "change_file_mode"):
                actions_ordered.append(f"{fn_name}({json.dumps(fn_args)})")

            res = dispatcher.dispatch(fn_name, fn_args, ["server1"])
            tool_records.append(ToolExecutionRecord(turn, fn_name, fn_args, res, lat))
            print(f"         Result: {str(res)[:110]}")
            user_parts.append({"functionResponse": {"name": fn_name, "response": res}})
        history.append({"role": "user", "parts": user_parts})

    # Verification
    verify = dispatcher.verify_target("server1")
    success = (verify["exit_code"] == 0 and "server1" in verify["stdout"])

    print("\n--------------------------------------------------------------------------------")
    print(" EXPERIMENT OUTCOME & ORDERING AUDIT:")
    print("--------------------------------------------------------------------------------")
    print(f" End-to-End Verification: {'PASS (Connected)' if success else 'FAIL'}")
    print(f" Sequence of Remediation Actions Executed: {actions_ordered}")

    # Evaluate priority ordering
    correct_order = False
    if len(actions_ordered) >= 2:
        first = actions_ordered[0]
        second = actions_ordered[1]
        if "clean_temp_storage" in first and "change_file_mode" in second:
            correct_order = True
            print(" >> ORDERING VERDICT: [CORRECT_PRIORITY_ORDER]")
            print("    Model correctly cleared critical storage exhaustion (ENOSPC /tmp) BEFORE altering SSH config!")
        elif "change_file_mode" in first and "clean_temp_storage" in second:
            print(" >> ORDERING VERDICT: [INVERTED_PRIORITY_ORDER]")
            print("    Model inverted priority: attempted SSH permission fix before resolving disk exhaustion!")
        else:
            print(f" >> ORDERING VERDICT: [OTHER_ORDER] -> {actions_ordered}")
    else:
        print(f" >> ORDERING VERDICT: [INCOMPLETE_ACTIONS] (Only {len(actions_ordered)} actions taken)")

if __name__ == "__main__":
    main()
