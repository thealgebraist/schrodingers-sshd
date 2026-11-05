#!/usr/bin/env python3
"""
test_hosts_deny.py

Instance 17: TCP Wrappers Silent Drop (/etc/hosts.deny) vs Downstream Target Decoy
Topology:
  [mh-client] --> [mh-server-1 (bastion)] --> [mh-server-3 (internal gateway)] --> [mh-server-2 (target)]

Root Cause:
  mh-server-3 has /etc/hosts.deny: sshd: ALL
Decoy:
  mh-server-2 has authorized_keys chmod 0777 (StrictModes bait)

Observable Error:
  kex_exchange_identification: read: Connection reset by peer
  Connection reset by UNKNOWN port 65535

Test:
  Does Gemini identify that hop 2 (server3) dropped the connection via hosts.deny,
  or does it fall for the bait on server2?
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

def setup_instance_17(lab_dir: Path) -> None:
    # 1. Reset baseline
    subprocess.run([str(lab_dir / "start.sh")], cwd=lab_dir, stdout=subprocess.DEVNULL, check=True)
    subprocess.run(
        ["sudo", "docker", "stop", "mh-server-4", "mh-server-5", "mh-server-6", "mh-server-7", "mh-server-8"],
        stdout=subprocess.DEVNULL,
        check=True,
    )
    # Ensure server1 and server3 and server2 are clean
    for s in ["mh-server-1", "mh-server-2", "mh-server-3"]:
        subprocess.run(["sudo", "docker", "exec", "--user", "root", s, "sh", "-c", "echo '' > /etc/hosts.deny"], check=True)
        subprocess.run(["sudo", "docker", "exec", "--user", "root", s, "chmod", "0755", "/home/deploy"], check=True)
        subprocess.run(["sudo", "docker", "exec", "--user", "root", s, "chmod", "0700", "/home/deploy/.ssh"], check=True)
        subprocess.run(["sudo", "docker", "exec", "--user", "root", s, "chmod", "0600", "/home/deploy/.ssh/authorized_keys"], check=True)

    # 2. Inject ROOT CAUSE on mh-server-3: /etc/hosts.deny
    subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-3", "sh", "-c", "echo 'sshd: ALL' > /etc/hosts.deny"], check=True)

    # 3. Inject DECOY BAIT on mh-server-2: authorized_keys chmod 0777
    subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-2", "chmod", "0777", "/home/deploy/.ssh/authorized_keys"], check=True)

    print("Instance 17 successfully setup:")
    print("  ROOT CAUSE: mh-server-3 /etc/hosts.deny contains 'sshd: ALL'")
    print("  DECOY BAIT: mh-server-2 authorized_keys is mode 0777")

def main() -> None:
    lab_dir = Path("/home/agent1/testsshprobs/lab/multihop")
    gk = (lab_dir / "gemini.key.txt").read_text().strip()
    setup_instance_17(lab_dir)

    dispatcher = LabDispatcher(lab_dir)
    orig_dispatch = dispatcher.dispatch

    def patched_dispatch(name: str, args: dict[str, Any], allowed_servers: list[str]) -> dict[str, Any]:
        if name == "clear_hosts_deny":
            server = str(args["server"])
            cname = f"mh-server-{server.removeprefix('server')}"
            res = dispatcher.execute_host_command(["sudo", "docker", "exec", "--user", "root", cname, "sh", "-c", "echo '' > /etc/hosts.deny"])
            return {"status": "SUCCESS", "server": server, "cleared_hosts_deny": True, "result": res}
        if name == "inspect_server" and args.get("view") == "hosts_deny":
            server = str(args["server"])
            cname = f"mh-server-{server.removeprefix('server')}"
            return dispatcher.execute_host_command(["sudo", "docker", "exec", cname, "cat", "/etc/hosts.deny"])
        return orig_dispatch(name, args, allowed_servers)
    dispatcher.dispatch = patched_dispatch

    tools = [
        ToolDefinition(
            name="connect",
            description="Attempt a remote hostname check from the client to server2 via jump chain server1,server3. Returns exit_code, stdout, stderr.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": ["server2"]},
                    "verbose": {"type": "boolean"},
                },
                "required": ["target", "verbose"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="inspect_server",
            description="Read-only view of server configuration, logs, hosts_deny, or file permissions.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1", "server2", "server3"]},
                    "view": {"type": "string", "enum": ["hosts_deny", "logs", "auth_file_metadata", "sshd_config", "status"]},
                },
                "required": ["server", "view"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="clear_hosts_deny",
            description="Clear TCP wrappers /etc/hosts.deny access restrictions on a server.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1", "server2", "server3"]},
                },
                "required": ["server"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="change_file_mode",
            description="Change file permission octal mode (e.g. 0600) on a target file.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1", "server2", "server3"]},
                    "path": {"type": "string"},
                    "mode": {"type": "string"},
                },
                "required": ["server", "path", "mode"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="change_sshd_directive",
            description="Update an OpenSSH daemon directive and reload sshd.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": ["server1", "server2", "server3"]},
                    "directive": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["server", "directive", "value"],
                "additionalProperties": False,
            },
        ),
    ]

    prompt = (
        "Diagnose and fix the SSH connection failure from this client to server2. "
        "The connection routes via jump hosts server1,server3. "
        "First call connect(target='server2', verbose=True) to observe the failure. "
        "Identify the root cause, apply the minimal fix, and verify with connect."
    )

    agent = GeminiArgonAgent(gk, model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), thinking_budget=1024)
    history: list[dict[str, Any]] = [{"role": "user", "parts": [{"text": prompt}]}]
    actions_taken: list[str] = []

    print("\nStarting multi-turn agent evaluation on Instance 17 (TCP Wrappers vs Decoy)...")
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
            if fn_name in ("clear_hosts_deny", "change_file_mode", "change_sshd_directive"):
                actions_taken.append(f"{fn_name}({json.dumps(fn_args)})")
            res = dispatcher.dispatch(fn_name, fn_args, ["server1", "server2", "server3"])
            trunc_res = str(res)[:120]
            print(f"         Result: {trunc_res}")
            user_parts.append({"functionResponse": {"name": fn_name, "response": res}})
        history.append({"role": "user", "parts": user_parts})

    print("\n--------------------------------------------------------------------------------")
    print("EXPERIMENT EVALUATION:")
    print("--------------------------------------------------------------------------------")
    print(f"Actions taken: {actions_taken}")
    
    # Did it touch server2 (the decoy)?
    touched_decoy = any("server2" in a for a in actions_taken)
    cleared_root = any("clear_hosts_deny" in a and "server3" in a for a in actions_taken)

    if touched_decoy and not cleared_root:
        print(">> VERDICT: [MISDIAGNOSED_DECOY_TRAP] Model attacked server2 decoy permissions, missing server3 hosts.deny!")
    elif cleared_root and not touched_decoy:
        print(">> VERDICT: [SUCCESS_ROOT_CAUSE_ISOLATED] Model correctly identified server3 TCP wrappers drop!")
    elif cleared_root and touched_decoy:
        print(">> VERDICT: [MIXED_ORDER_OR_DUAL] Model fixed both, but fell for decoy first.")
    else:
        print(">> VERDICT: [UNKNOWN_OR_INCOMPLETE] Model failed to resolve.")

if __name__ == "__main__":
    main()
