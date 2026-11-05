#!/usr/bin/env python3
"""
test_krl_revocation.py

Instance 20: Key Revocation List (RevokedKeys KRL) vs Permissions Bait
Topology:
  8-server cascade to mh-server-8.

Root Cause:
  mh-server-8 has RevokedKeys /etc/ssh/revoked.krl in sshd_config.
  The client's valid ed25519 key is revoked in the KRL binary list.
  File permissions on ~/.ssh (0700) and authorized_keys (0600) are pristine.

Observable Error:
  deploy@server8: Permission denied (publickey)

Cognitive Trap:
  The observable error is identical to StrictModes permission failure.
  Fast LLMs overwhelmingly assume authorized_keys has bad permissions or is missing,
  repeatedly attempting chmod or append_client_public_key (which re-adds the same revoked key).
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

def setup_krl_revocation(lab_dir: Path) -> None:
    # 1. Reset baseline
    subprocess.run([str(lab_dir / "start.sh")], cwd=lab_dir, stdout=subprocess.DEVNULL, check=True)
    
    # 2. Inject KRL on mh-server-8
    krl_script = (
        "ssh-keygen -q -k -f /etc/ssh/revoked.krl /home/deploy/.ssh/authorized_keys && "
        "chmod 0644 /etc/ssh/revoked.krl && "
        "printf '\\nRevokedKeys /etc/ssh/revoked.krl\\n' >> /etc/ssh/sshd_config && "
        "/usr/sbin/sshd -t -f /etc/ssh/sshd_config && kill -HUP 1"
    )
    subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-8", "sh", "-c", krl_script], check=True)
    print("Instance 20 successfully setup: mh-server-8 has RevokedKeys active.")

def main() -> None:
    lab_dir = Path("/home/agent1/testsshprobs/lab/multihop")
    gk = (lab_dir / "gemini.key.txt").read_text().strip()
    setup_krl_revocation(lab_dir)

    dispatcher = LabDispatcher(lab_dir)
    orig_dispatch = dispatcher.dispatch

    def patched_dispatch(name: str, args: dict[str, Any], allowed_servers: list[str]) -> dict[str, Any]:
        if name == "remove_revocation_list":
            server = str(args["server"])
            cname = f"mh-server-{server.removeprefix('server')}"
            clean_cmd = "sed -i '/RevokedKeys/d' /etc/ssh/sshd_config && kill -HUP 1"
            res = dispatcher.execute_host_command(["sudo", "docker", "exec", "--user", "root", cname, "sh", "-c", clean_cmd])
            return {"status": "SUCCESS", "server": server, "revocation_removed": True, "result": res}
        return orig_dispatch(name, args, allowed_servers)
    dispatcher.dispatch = patched_dispatch

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
            description="Read-only view of server configuration, logs, or file permissions.",
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
            name="remove_revocation_list",
            description="Remove RevokedKeys directive from server sshd_config and reload daemon.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": allowed},
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
                    "server": {"type": "string", "enum": allowed},
                    "path": {"type": "string"},
                    "mode": {"type": "string"},
                },
                "required": ["server", "path", "mode"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="append_client_public_key",
            description="Append the client public key to the target server's authorized_keys.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": allowed},
                },
                "required": ["server"],
                "additionalProperties": False,
            },
        ),
    ]

    prompt = (
        "Diagnose and fix the SSH connection failure from client to server8. "
        "First call connect(target='server8', verbose=True) to observe the failure. "
        "Identify the root cause, apply the sound minimal fix, and verify with connect."
    )

    agent = GeminiArgonAgent(gk, model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), thinking_budget=1024)
    history: list[dict[str, Any]] = [{"role": "user", "parts": [{"text": prompt}]}]
    actions_taken: list[str] = []

    print("\nStarting multi-turn agent evaluation on Instance 20 (RevokedKeys KRL vs Permissions)...")
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
            if fn_name in ("remove_revocation_list", "change_file_mode", "append_client_public_key"):
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
    
    fixed_krl = any("remove_revocation_list" in a and "server8" in a for a in actions_taken)
    fell_for_key_trap = any("change_file_mode" in a or "append_client_public_key" in a for a in actions_taken)

    if fell_for_key_trap and not fixed_krl:
        print(">> VERDICT: [MISDIAGNOSED_REDUNDANT_KEY_APPEND] Model repeatedly modified authorized_keys/permissions, missing RevokedKeys KRL!")
    elif fixed_krl and not fell_for_key_trap:
        print(">> VERDICT: [SUCCESS_ROOT_CAUSE_ISOLATED] Model inspected sshd_config, identified RevokedKeys, and removed it!")
    elif fixed_krl and fell_for_key_trap:
        print(">> VERDICT: [MIXED_REPAIR] Model fell for key trap first before removing KRL.")
    else:
        print(f">> VERDICT: [UNKNOWN_FAILURE] actions: {actions_taken}")

if __name__ == "__main__":
    main()
