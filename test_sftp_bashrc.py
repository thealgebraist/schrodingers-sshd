#!/usr/bin/env python3
"""
test_sftp_bashrc.py

Instance 18: Polluted stdout in user .bashrc breaking binary SFTP/SCP framing.
Topology:
  [mh-client] --> [mh-server-1]

Root Cause:
  /home/deploy/.bashrc has unbuffered echo:
    echo "Welcome to Cluster Node 1! All systems operational."
  This pollutes stdout for non-interactive binary sessions (SFTP subsystem).

Observable Error:
  Received message too long 1466262131
  Ensure /usr/lib/openssh/sftp-server is executable...

Test:
  Evaluates whether Gemini 3.8 Flash recognizes the ASCII packet length aliasing
  ('Welc' == 1466262131) and guards the shell output, or misdiagnoses by mutating
  sshd_config subsystem directives or permissions.
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

def setup_instance_18(lab_dir: Path) -> None:
    # 1. Reset baseline
    subprocess.run([str(lab_dir / "start.sh")], cwd=lab_dir, stdout=subprocess.DEVNULL, check=True)
    subprocess.run(
        ["sudo", "docker", "stop", "mh-server-2", "mh-server-3", "mh-server-4", "mh-server-5", "mh-server-6", "mh-server-7", "mh-server-8"],
        stdout=subprocess.DEVNULL,
        check=True,
    )
    # Ensure standard permissions on server1
    subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0755", "/home/deploy"], check=True)
    subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0700", "/home/deploy/.ssh"], check=True)
    subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0600", "/home/deploy/.ssh/authorized_keys"], check=True)

    # 2. Inject ROOT CAUSE: echo in /home/deploy/.bashrc
    bashrc_payload = 'echo "Welcome to Cluster Node 1! All systems operational."\n'
    subprocess.run(["sudo", "docker", "exec", "--user", "deploy", "mh-server-1", "sh", "-c", f"echo '{bashrc_payload}' > /home/deploy/.bashrc"], check=True)

    print("Instance 18 successfully setup: /home/deploy/.bashrc on server1 contains unbuffered banner echo.")

def main() -> None:
    lab_dir = Path("/home/agent1/testsshprobs/lab/multihop")
    gk = (lab_dir / "gemini.key.txt").read_text().strip()
    setup_instance_18(lab_dir)

    dispatcher = LabDispatcher(lab_dir)
    orig_dispatch = dispatcher.dispatch

    def patched_dispatch(name: str, args: dict[str, Any], allowed_servers: list[str]) -> dict[str, Any]:
        if name == "sftp_test":
            # Attempt sftp batch command to test binary subsystem framing
            cmd = ["sudo", "docker", "exec", "mh-client", "sh", "-c", "echo 'ls' | sftp -b - deploy@server1 2>&1"]
            res = dispatcher.execute_host_command(cmd)
            return {"exit_code": res["exit_code"], "output": res["stdout"] + "\n" + res["stderr"]}
        if name == "inspect_file":
            server = str(args["server"])
            cname = f"mh-server-{server.removeprefix('server')}"
            path = str(args["path"])
            return dispatcher.execute_host_command(["sudo", "docker", "exec", cname, "cat", path])
        if name == "edit_bashrc_guard":
            server = str(args["server"])
            cname = f"mh-server-{server.removeprefix('server')}"
            guard = '[ -t 0 ] && echo "Welcome to Cluster Node 1! All systems operational."\n'
            return dispatcher.execute_host_command(["sudo", "docker", "exec", "--user", "deploy", cname, "sh", "-c", f"echo '{guard}' > /home/deploy/.bashrc"])
        return orig_dispatch(name, args, allowed_servers)
    dispatcher.dispatch = patched_dispatch

    tools = [
        ToolDefinition(
            name="sftp_test",
            description="Execute SFTP batch command from client to server1 to test binary subsystem protocol transfer.",
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
            name="inspect_server",
            description="Read-only view of server configuration, sshd_config, logs, or status.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1"]},
                    "view": {"type": "string", "enum": ["logs", "auth_file_metadata", "sshd_config", "status"]},
                },
                "required": ["server", "view"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="inspect_file",
            description="Read file contents on a target server.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1"]},
                    "path": {"type": "string"},
                },
                "required": ["server", "path"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="edit_bashrc_guard",
            description="Add an interactive terminal guard [ -t 0 ] around banner echos in user .bashrc.",
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
            name="change_sshd_directive",
            description="Update an OpenSSH daemon directive and reload sshd.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1"]},
                    "directive": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["server", "directive", "value"],
                "additionalProperties": False,
            },
        ),
    ]

    prompt = (
        "Diagnose and fix the binary transfer failure from this client to server1. "
        "Automated SFTP file transfers fail with an error. "
        "First call sftp_test(server='server1') to observe the failure. "
        "Diagnose the root cause, apply the sound fix, and verify with sftp_test."
    )

    agent = GeminiArgonAgent(gk, model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), thinking_budget=1024)
    history: list[dict[str, Any]] = [{"role": "user", "parts": [{"text": prompt}]}]
    actions_taken: list[str] = []

    print("\nStarting multi-turn agent evaluation on Instance 18 (Polluted stdout in .bashrc)...")
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
            if fn_name in ("edit_bashrc_guard", "change_sshd_directive"):
                actions_taken.append(f"{fn_name}({json.dumps(fn_args)})")
            res = dispatcher.dispatch(fn_name, fn_args, ["server1"])
            trunc_res = str(res)[:120]
            print(f"         Result: {trunc_res}")
            user_parts.append({"functionResponse": {"name": fn_name, "response": res}})
        history.append({"role": "user", "parts": user_parts})

    print("\n--------------------------------------------------------------------------------")
    print("EXPERIMENT EVALUATION:")
    print("--------------------------------------------------------------------------------")
    print(f"Actions taken: {actions_taken}")
    
    mutated_sshd = any("change_sshd_directive" in a for a in actions_taken)
    guarded_bashrc = any("edit_bashrc_guard" in a for a in actions_taken)

    if mutated_sshd and not guarded_bashrc:
        print(">> VERDICT: [MISDIAGNOSED_PROTOCOL_LAYER] Model blamed sshd_config Subsystem instead of .bashrc stdout pollution!")
    elif guarded_bashrc and not mutated_sshd:
        print(">> VERDICT: [SUCCESS_ROOT_CAUSE_ISOLATED] Model recognized binary packet framing corruption from .bashrc echo!")
    else:
        print(f">> VERDICT: [COMPLEX_OR_OTHER] actions: {actions_taken}")

if __name__ == "__main__":
    main()
