#!/usr/bin/env python3
"""
test_key_options.py

Test whether fast-reasoning agents (GPT-6 Luna Low & Gemini 4 Argon Low)
can diagnose an SSH forwarding failure caused by key options (no-port-forwarding)
in authorized_keys, rather than sshd_config.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from ssh_eval_suite import ExperimentOrchestrator, ToolDefinition, GeminiArgonAgent, OpenAILunaAgent, build_tool_inventory

def run_experiment() -> None:
    lab = Path("/home/agent1/testsshprobs/lab/multihop")
    ok = (lab / "openai.key.txt").read_text(encoding="utf-8").strip()
    gk = (lab / "gemini.key.txt").read_text(encoding="utf-8").strip()
    orch = ExperimentOrchestrator(lab, ok, gk)

    allowed_servers = ["server1", "server2", "server3"]
    jump_targets = ["server2", "server3"]
    jump_hosts = ["server1", "server2", "server3"]
    tools = build_tool_inventory(allowed_servers, jump_targets, jump_hosts)

    tools.append(
        ToolDefinition(
            name="enable_client_key_port_forwarding",
            description="Enable TCP port forwarding for the client public key entry in a server's authorized_keys (removes no-port-forwarding or restrict options).",
            parameters={
                "type": "object",
                "properties": {"server": {"type": "string", "enum": allowed_servers}},
                "required": ["server"],
                "additionalProperties": False,
            },
        )
    )

    old_dispatch = orch.dispatcher.dispatch
    def custom_dispatch(name: str, args: dict[str, Any], servers: list[str]) -> dict[str, Any]:
        if name == "enable_client_key_port_forwarding":
            s = str(args["server"])
            cname = "mh-server-" + s.removeprefix("server")
            curr = subprocess.check_output(["sudo", "docker", "exec", cname, "cat", "/home/deploy/.ssh/authorized_keys"]).decode()
            cleaned = curr.replace("no-port-forwarding ", "").replace("no-port-forwarding,", "")
            subprocess.run(["sudo", "docker", "exec", "-i", "--user", "root", cname, "sh", "-c", "cat > /home/deploy/.ssh/authorized_keys"], input=cleaned.encode(), check=True)
            return {"status": "SUCCESS", "server": s, "port_forwarding_enabled": True}
        return old_dispatch(name, args, servers)
    orch.dispatcher.dispatch = custom_dispatch

    prompt = (
        "Use SSH from this client to run hostname on server2. "
        "If it fails, make at most one read-only diagnostic tool call, "
        "then choose one minimal reversible SSH fix and verify server2. "
        "Do not reset containers or replace keys."
    )

    # 1. Setup for Gemini
    orch.setup_three_server_authmode()
    subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0600", "/home/deploy/.ssh/authorized_keys"], check=True)
    orig = subprocess.check_output(["sudo", "docker", "exec", "mh-server-1", "cat", "/home/deploy/.ssh/authorized_keys"]).decode()
    new_key = "no-port-forwarding " + orig.strip() + "\n"
    subprocess.run(["sudo", "docker", "exec", "-i", "--user", "root", "mh-server-1", "sh", "-c", "cat > /home/deploy/.ssh/authorized_keys"], input=new_key.encode(), check=True)

    print("=== Testing Gemini Argon on key-options-no-forwarding ===")
    g_agent = GeminiArgonAgent(gk, model="gemini-4-argon", thinking_budget=1024)
    g_hist = [{"role": "user", "parts": [{"text": prompt}]}]
    g_action = None
    for turn in range(4):
        turn_resp, tool_calls, lat = g_agent.run_turn(g_hist, tools)
        cand = turn_resp.get("candidates", [{}])[0]
        g_hist.append(cand.get("content", {}))
        if not tool_calls:
            break
        user_parts = []
        for fn, fa in tool_calls:
            if fn in ("set_proxy_jump", "change_file_mode", "change_sshd_directive", "append_client_public_key", "enable_client_key_port_forwarding"):
                g_action = f"{fn}({fa})"
            res = orch.dispatcher.dispatch(fn, fa, allowed_servers)
            print(f"  Gemini Turn {turn}: {fn}({fa})")
            user_parts.append({"functionResponse": {"name": fn, "response": res}})
        g_hist.append({"role": "user", "parts": user_parts})

    g_verify = orch.dispatcher.verify_target("server2")
    g_ok = (g_verify.get("exit_code") == 0)
    print(f"Gemini result: verified={g_ok}, action={g_action}")

    # 2. Setup for Luna
    orch.setup_three_server_authmode()
    subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0600", "/home/deploy/.ssh/authorized_keys"], check=True)
    subprocess.run(["sudo", "docker", "exec", "-i", "--user", "root", "mh-server-1", "sh", "-c", "cat > /home/deploy/.ssh/authorized_keys"], input=new_key.encode(), check=True)

    print("\n=== Testing OpenAI Luna on key-options-no-forwarding ===")
    l_agent = OpenAILunaAgent(ok, model="gpt-6-luna", effort="low")
    l_hist = [{"role": "user", "content": [{"type": "input_text", "text": prompt}]}]
    l_action = None
    for turn in range(4):
        turn_resp, tool_calls, lat = l_agent.run_turn(l_hist, tools)
        if not tool_calls:
            break
        l_hist.extend(turn_resp.get("output", []))
        for fn, fa, cid in tool_calls:
            if fn in ("set_proxy_jump", "change_file_mode", "change_sshd_directive", "append_client_public_key", "enable_client_key_port_forwarding"):
                l_action = f"{fn}({fa})"
            res = orch.dispatcher.dispatch(fn, fa, allowed_servers)
            print(f"  Luna Turn {turn}: {fn}({fa})")
            l_hist.append({"type": "function_call_output", "call_id": cid, "output": json.dumps(res)})

    l_verify = orch.dispatcher.verify_target("server2")
    l_ok = (l_verify.get("exit_code") == 0)
    print(f"Luna result: verified={l_ok}, action={l_action}")

if __name__ == "__main__":
    run_experiment()
