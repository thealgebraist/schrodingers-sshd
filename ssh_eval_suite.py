#!/usr/bin/env python3
"""
ssh_eval_suite.py

Automated Evaluation Suite for Autonomous Diagnostic Agents on Cascaded SSH Networks.
Evaluates:
  - OpenAI: gpt-6-luna (Responses API, reasoning: {"effort": "low"})
  - Google Gemini: gemini-4-argon (REST API, thinkingConfig: {"thinkingBudget": 1024})

Strictly typed under PEP 484 / PEP 526 / PEP 585 / PEP 604 annotations.
"""
from __future__ import annotations

import abc
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Final, List, Literal, Mapping, Optional, Sequence, Tuple, Union

# ==============================================================================
# 1. TYPE DEFINITIONS & DATA CONTRACTS
# ==============================================================================

ServerAlias = str
ViewType = str
DirectiveType = str

@dataclasses.dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any]

@dataclasses.dataclass
class ToolExecutionRecord:
    turn_index: int
    tool_name: str
    tool_args: dict[str, Any]
    result: dict[str, Any]
    latency_seconds: float

@dataclasses.dataclass
class TrialResult:
    trial_id: str
    model: str
    reasoning_tier: str
    fault_scenario: str
    topology: str
    initial_exit_code: int
    initial_stderr: str
    tool_records: list[ToolExecutionRecord]
    final_response_text: str
    final_thinking_text: str
    final_repair_action: Optional[str]
    verification_exit_code: int
    verification_stdout: str
    task_success: bool
    misdiagnosis_category: str
    total_duration_seconds: float

# ==============================================================================
# 2. LAB ENVIRONMENT DISPATCHER (DOCKER / QEMU INTERACTION)
# ==============================================================================

class LabDispatcher:
    def __init__(self, root_dir: Path) -> None:
        self.root_dir: Final[Path] = root_dir
        self.client_config_path: Final[Path] = root_dir / "client" / ".ssh" / "config"
        self.client_auth_keys: Final[Path] = root_dir / "authorized_keys"

    def execute_host_command(self, argv: Sequence[str], timeout: int = 20) -> dict[str, Any]:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }

    def verify_target(self, target: str) -> dict[str, Any]:
        return self.execute_host_command(
            ["sudo", "docker", "exec", "mh-client", "ssh", "-o", "ConnectTimeout=5", target, "hostname"]
        )

    def dispatch(self, name: str, args: dict[str, Any], allowed_servers: list[str]) -> dict[str, Any]:
        if name == "connect":
            target: str = str(args["target"])
            verbose: bool = bool(args.get("verbose", False))
            cmd: list[str] = ["sudo", "docker", "exec", "mh-client", "ssh"]
            if verbose:
                cmd.append("-vvv")
            cmd.extend([target, "hostname"])
            return self.execute_host_command(cmd, timeout=15)

        if name == "inspect_client":
            view: str = str(args["view"])
            if view == "effective_ssh_options":
                target = str(args.get("target", "server4"))
                return self.execute_host_command(["sudo", "docker", "exec", "mh-client", "ssh", "-G", target])
            if view == "client_config":
                return self.execute_host_command(["sudo", "docker", "exec", "mh-client", "cat", "/home/deploy/.ssh/config"])
            if view == "network_attachments":
                attachments: dict[str, Any] = {}
                for s in allowed_servers:
                    cname = f"mh-server-{s.removeprefix('server')}"
                    res = self.execute_host_command(["sudo", "docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", cname])
                    try:
                        attachments[s] = json.loads(res["stdout"])
                    except json.JSONDecodeError:
                        attachments[s] = res["stdout"]
                return {"attachments": attachments}
            if view == "credential_metadata":
                script = "stat -c '%a %U:%G %n' /home/deploy/.ssh /home/deploy/.ssh/id_ed25519 /home/deploy/.ssh/config"
                return self.execute_host_command(["sudo", "docker", "exec", "mh-client", "sh", "-lc", script])
            return {"error": f"Unknown client view: {view}"}

        if name == "inspect_server":
            server: str = str(args["server"])
            view = str(args["view"])
            cname = f"mh-server-{server.removeprefix('server')}"
            if view == "logs":
                return self.execute_host_command(["sudo", "docker", "logs", "--tail", "35", cname])
            if view == "auth_file_metadata":
                script = "stat -c '%a %U:%G %n' /home/deploy /home/deploy/.ssh /home/deploy/.ssh/authorized_keys"
                return self.execute_host_command(["sudo", "docker", "exec", cname, "sh", "-lc", script])
            if view == "authorized_keys_entries":
                return self.execute_host_command(["sudo", "docker", "exec", cname, "cat", "/home/deploy/.ssh/authorized_keys"])
            if view == "sshd_config":
                return self.execute_host_command(["sudo", "docker", "exec", cname, "cat", "/etc/ssh/sshd_config"])
            if view == "status":
                return self.execute_host_command(["sudo", "docker", "inspect", "--format", "{{.Name}} state={{.State.Status}}", cname])
            return {"error": f"Unknown server view: {view}"}

        if name == "change_file_mode":
            server = str(args["server"])
            path: str = str(args["path"])
            mode: str = str(args["mode"])
            cname = f"mh-server-{server.removeprefix('server')}"
            return self.execute_host_command(["sudo", "docker", "exec", "--user", "root", cname, "chmod", mode, path])

        if name == "change_sshd_directive":
            server = str(args["server"])
            directive: str = str(args["directive"])
            val: str = str(args["value"])
            reload_daemon: bool = bool(args.get("reload", True))
            cname = f"mh-server-{server.removeprefix('server')}"

            # Read current config
            curr = self.execute_host_command(["sudo", "docker", "exec", cname, "cat", "/etc/ssh/sshd_config"])
            if curr["exit_code"] != 0:
                return curr

            lines = curr["stdout"].splitlines()
            active_indices = [i for i, line in enumerate(lines) if line.strip().lower().startswith(directive.lower() + " ")]
            if active_indices:
                lines[active_indices[0]] = f"{directive} {val}"
                for i in reversed(active_indices[1:]):
                    del lines[i]
            else:
                lines.append(f"{directive} {val}")

            new_content = "\n".join(lines) + "\n"
            writer = subprocess.run(
                ["sudo", "docker", "exec", "-i", "--user", "root", cname, "sh", "-c", "cat > /etc/ssh/sshd_config"],
                input=new_content,
                text=True,
                capture_output=True,
            )
            if writer.returncode != 0:
                return {"error": "Failed to write sshd_config", "stderr": writer.stderr}

            if reload_daemon:
                self.execute_host_command(["sudo", "docker", "exec", "--user", "root", cname, "kill", "-HUP", "1"])
            return {"status": "SUCCESS", "directive": directive, "new_value": val, "reloaded": reload_daemon}

        if name == "set_proxy_jump":
            target = str(args["target"])
            jump: str = str(args["jump"])
            raw_cfg = self.client_config_path.read_text(encoding="utf-8")
            lines = raw_cfg.splitlines(keepends=True)
            host_idx = -1
            for i, line in enumerate(lines):
                if line.strip().lower() == f"host {target}":
                    host_idx = i
                    break
            if host_idx == -1:
                return {"error": f"Target host {target} not found in client config"}

            end_idx = len(lines)
            for i in range(host_idx + 1, len(lines)):
                if lines[i].lstrip().lower().startswith("host "):
                    end_idx = i
                    break

            pj_idx = -1
            for i in range(host_idx + 1, end_idx):
                if lines[i].lstrip().lower().startswith("proxyjump "):
                    pj_idx = i
                    break

            if pj_idx != -1:
                lines[pj_idx] = f"    ProxyJump {jump}\n"
            else:
                lines.insert(host_idx + 1, f"    ProxyJump {jump}\n")

            self.client_config_path.write_text("".join(lines), encoding="utf-8")
            return {"status": "PROXYJUMP_UPDATED", "target": target, "new_jump": jump}

        if name == "append_client_public_key":
            server = str(args["server"])
            cname = f"mh-server-{server.removeprefix('server')}"
            pub_bytes = self.client_auth_keys.read_text(encoding="utf-8").strip()
            # Append key
            writer = subprocess.run(
                ["sudo", "docker", "exec", "-i", "--user", "root", cname, "sh", "-c", "cat >> /home/deploy/.ssh/authorized_keys"],
                input=pub_bytes + "\n",
                text=True,
                capture_output=True,
            )
            return {"status": "KEY_APPENDED", "server": server, "exit_code": writer.returncode}

        return {"error": f"Unknown tool: {name}"}

# ==============================================================================
# 3. BASE AGENT INTERFACE
# ==============================================================================

class BaseDiagnosticAgent(abc.ABC):
    @abc.abstractmethod
    def run_turn(
        self,
        conversation_history: list[dict[str, Any]],
        tools: list[ToolDefinition],
    ) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]], float]:
        """
        Runs one agent API inference turn.
        Returns:
          - raw_model_response
          - list of (tool_name, tool_arguments) requested
          - turn_latency_seconds
        """
        pass

# ==============================================================================
# 4. OPENAI LUNA 6 LOW AGENT IMPLEMENTATION
# ==============================================================================

class OpenAILunaAgent(BaseDiagnosticAgent):
    def __init__(self, api_key: str, model: str = "gpt-6-luna", effort: str = "low") -> None:
        self.api_key: Final[str] = api_key
        self.model: Final[str] = model
        self.effort: Final[str] = effort
        self.endpoint: Final[str] = "https://api.openai.com/v1/responses"

    def _convert_tools_to_openai_schema(self, tools: list[ToolDefinition]) -> list[dict[str, Any]]:
        openai_tools: list[dict[str, Any]] = []
        for t in tools:
            openai_tools.append({
                "type": "function",
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
                "strict": True,
            })
        return openai_tools

    def run_turn(
        self,
        conversation_history: list[dict[str, Any]],
        tools: list[ToolDefinition],
    ) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any], str]], float]:
        payload: dict[str, Any] = {
            "model": self.model,
            "reasoning": {"effort": self.effort, "summary": "auto"},
            "include": ["reasoning.encrypted_content"],
            "input": conversation_history,
            "tools": self._convert_tools_to_openai_schema(tools),
            "tool_choice": "auto",
            "store": False,
        }

        started = time.time()
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                body = resp.read().decode("utf-8")
                latency = round(time.time() - started, 4)
                data = json.loads(body)

                tool_calls: list[tuple[str, dict[str, Any], str]] = []
                for item in data.get("output", []):
                    if item.get("type") == "function_call":
                        fn_name = str(item.get("name"))
                        call_id = str(item.get("call_id", f"call_{len(tool_calls)}"))
                        try:
                            fn_args = json.loads(str(item.get("arguments", "{}")))
                        except json.JSONDecodeError:
                            fn_args = {}
                        tool_calls.append((fn_name, fn_args, call_id))

                return data, tool_calls, latency
        except urllib.error.HTTPError as exc:
            err_text = exc.read().decode("utf-8", "replace")
            raise RuntimeError(f"OpenAI API HTTP {exc.code}: {err_text}") from exc

# ==============================================================================
# 5. GOOGLE GEMINI 4 ARGON LOW AGENT IMPLEMENTATION
# ==============================================================================

class GeminiArgonAgent(BaseDiagnosticAgent):
    def __init__(self, api_key: str, model: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), thinking_budget: int = 1024) -> None:
        self.api_key: Final[str] = api_key
        self.model: Final[str] = model
        self.thinking_budget: Final[int] = thinking_budget
        self.endpoint: Final[str] = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        )

    def _convert_tools_to_gemini_schema(self, tools: list[ToolDefinition]) -> list[dict[str, Any]]:
        # Map JSON schema types to Gemini type representations
        def clean_schema(prop: dict[str, Any]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            p_type = prop.get("type", "STRING")
            if p_type == "string":
                out["type"] = "STRING"
            elif p_type == "boolean":
                out["type"] = "BOOLEAN"
            elif p_type == "object":
                out["type"] = "OBJECT"
            elif p_type == "array":
                out["type"] = "ARRAY"
            else:
                out["type"] = str(p_type).upper()

            if "enum" in prop:
                out["enum"] = prop["enum"]
            if "description" in prop:
                out["description"] = prop["description"]
            if "properties" in prop:
                out["properties"] = {k: clean_schema(v) for k, v in prop["properties"].items()}
            if "required" in prop:
                out["required"] = prop["required"]
            return out

        func_decls: list[dict[str, Any]] = []
        for t in tools:
            func_decls.append({
                "name": t.name,
                "description": t.description,
                "parameters": clean_schema(t.parameters),
            })
        return [{"functionDeclarations": func_decls}]

    def run_turn(
        self,
        conversation_history: list[dict[str, Any]],
        tools: list[ToolDefinition],
    ) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]], float]:
        payload: dict[str, Any] = {
            "contents": conversation_history,
            "tools": self._convert_tools_to_gemini_schema(tools),
            "generationConfig": {
                "thinkingConfig": {"thinkingBudget": self.thinking_budget}
            },
        }

        started = time.time()
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    body = resp.read().decode("utf-8")
                    latency = round(time.time() - started, 4)
                    data = json.loads(body)

                    tool_calls: list[tuple[str, dict[str, Any]]] = []
                    cand = data.get("candidates", [{}])[0]
                    content = cand.get("content", {})
                    for part in content.get("parts", []):
                        if "functionCall" in part:
                            fc = part["functionCall"]
                            tool_calls.append((fc.get("name", ""), fc.get("args", {})))

                    return data, tool_calls, latency
            except urllib.error.HTTPError as exc:
                err_text = exc.read().decode("utf-8", "replace")
                if exc.code == 429 and attempt < 3:
                    time.sleep(20)
                    continue
                raise RuntimeError(f"Gemini API HTTP {exc.code}: {err_text}") from exc
        raise RuntimeError("Gemini API: Exceeded retry attempts")

# ==============================================================================
# 6. TOOL INVENTORY BUILDER
# ==============================================================================

def build_tool_inventory(allowed_servers: list[str], jump_targets: list[str], jump_hosts: list[str]) -> list[ToolDefinition]:
    tools = [
        ToolDefinition(
            name="connect",
            description="Attempt a remote hostname check from the client to one target. Returns exit_code, stdout, stderr.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": allowed_servers},
                    "verbose": {"type": "boolean"},
                },
                "required": ["target", "verbose"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="inspect_client",
            description="Read-only view of client options, config, or network attachments.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": allowed_servers},
                    "view": {"type": "string", "enum": ["effective_ssh_options", "client_config", "network_attachments", "credential_metadata"]},
                },
                "required": ["target", "view"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="inspect_server",
            description="Read-only view of server sshd_config, logs, or file permissions.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": allowed_servers},
                    "view": {"type": "string", "enum": ["logs", "auth_file_metadata", "authorized_keys_entries", "sshd_config", "status"]},
                },
                "required": ["server", "view"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="change_sshd_directive",
            description="Modify an allowlisted directive in a server's sshd_config and optionally reload.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": allowed_servers},
                    "directive": {"type": "string", "enum": ["AllowTcpForwarding", "PasswordAuthentication", "PubkeyAuthentication", "PermitOpen"]},
                    "value": {"type": "string", "enum": ["yes", "no", "any"]},
                    "reload": {"type": "boolean"},
                },
                "required": ["server", "directive", "value", "reload"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="change_file_mode",
            description="Change the mode of permitted paths on a server (e.g. authorized_keys to 0600 or 0644).",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": allowed_servers},
                    "path": {"type": "string", "enum": ["/home/deploy", "/home/deploy/.ssh", "/home/deploy/.ssh/authorized_keys"]},
                    "mode": {"type": "string", "enum": ["0755", "0700", "0600", "0644"]},
                },
                "required": ["server", "path", "mode"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="append_client_public_key",
            description="Append the client public key to a server's authorized_keys.",
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": allowed_servers},
                },
                "required": ["server"],
                "additionalProperties": False,
            },
        ),
    ]
    if jump_targets and jump_hosts:
        tools.append(
            ToolDefinition(
                name="set_proxy_jump",
                description="Modify only the ProxyJump directive for one target alias in client config.",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "enum": jump_targets},
                        "jump": {"type": "string", "enum": jump_hosts},
                    },
                    "required": ["target", "jump"],
                    "additionalProperties": False,
                },
            )
        )
    return tools

# ==============================================================================
# 7. EXPERIMENT ORCHESTRATOR
# ==============================================================================

class ExperimentOrchestrator:
    def __init__(self, lab_dir: Path, openai_key: str, gemini_key: str) -> None:
        self.lab_dir: Final[Path] = lab_dir
        self.dispatcher: Final[LabDispatcher] = LabDispatcher(lab_dir)
        self.openai_key: Final[str] = openai_key
        self.gemini_key: Final[str] = gemini_key

    def setup_four_server_authmode(self) -> None:
        """Sets up 4-server topology with StrictModes 0666 on server2."""
        subprocess.run([str(self.lab_dir / "start.sh")], cwd=self.lab_dir, stdout=subprocess.DEVNULL, check=True)
        subprocess.run(["sudo", "docker", "stop", "mh-server-5", "mh-server-6", "mh-server-7", "mh-server-8"], stdout=subprocess.DEVNULL, check=True)
        # Inject fault: server2 authorized_keys 0666
        subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-2", "chmod", "0666", "/home/deploy/.ssh/authorized_keys"], check=True)

    def setup_four_server_forwarding(self) -> None:
        """Sets up 4-server topology with AllowTcpForwarding no on server2."""
        subprocess.run([str(self.lab_dir / "start.sh")], cwd=self.lab_dir, stdout=subprocess.DEVNULL, check=True)
        subprocess.run(["sudo", "docker", "stop", "mh-server-5", "mh-server-6", "mh-server-7", "mh-server-8"], stdout=subprocess.DEVNULL, check=True)
        # Inject fault: AllowTcpForwarding no on server2
        subprocess.run(["sudo", "docker", "exec", "mh-server-2", "sh", "-c", 'printf "\nAllowTcpForwarding no\n" >> /etc/ssh/sshd_config'], check=True)
        subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-2", "kill", "-HUP", "1"], check=True)

    def setup_two_server_authmode(self) -> None:
        """
        Sets up the MINIMAL 2-server baseline:
        client -> server1 (direct connection).
        Fault: server1 authorized_keys mode 0666.
        """
        subprocess.run([str(self.lab_dir / "start.sh")], cwd=self.lab_dir, stdout=subprocess.DEVNULL, check=True)
        subprocess.run(
            ["sudo", "docker", "stop", "mh-server-2", "mh-server-3", "mh-server-4", "mh-server-5", "mh-server-6", "mh-server-7", "mh-server-8"],
            stdout=subprocess.DEVNULL,
            check=True,
        )
        cfg = """Host *
    User deploy
    IdentityFile /home/deploy/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ConnectTimeout 4
    LogLevel ERROR

Host server1
    HostName server1
"""
        (self.lab_dir / "client" / ".ssh" / "config").write_text(cfg, encoding="utf-8")
        subprocess.run(
            ["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0666", "/home/deploy/.ssh/authorized_keys"],
            check=True,
        )

    def setup_three_server_authmode(self) -> None:
        """
        Sets up the MINIMAL 3-server topology:
        client -> server1 -> server2.
        Fault: server1 authorized_keys mode 0666.
        """
        subprocess.run([str(self.lab_dir / "start.sh")], cwd=self.lab_dir, stdout=subprocess.DEVNULL, check=True)
        subprocess.run(
            ["sudo", "docker", "stop", "mh-server-4", "mh-server-5", "mh-server-6", "mh-server-7", "mh-server-8"],
            stdout=subprocess.DEVNULL,
            check=True,
        )
        # Connect server2 directly to mh-1-3 so server1 can reach server2
        subprocess.run(
            ["sudo", "docker", "network", "connect", "--ip", "10.201.13.4", "--alias", "server2", "mh-1-3", "mh-server-2"],
            stdout=subprocess.DEVNULL,
            check=True,
        )

        # Write 3-server client config with server3 as alternate jump option
        cfg = """Host *
    User deploy
    IdentityFile /home/deploy/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ConnectTimeout 4
    LogLevel ERROR

Host server1
    HostName server1

Host server2
    HostName server2
    ProxyJump server1

Host server3
    HostName server3
    ProxyJump server1
"""
        (self.lab_dir / "client" / ".ssh" / "config").write_text(cfg, encoding="utf-8")
        # Injected fault on hop1 (server1):
        subprocess.run(
            ["sudo", "docker", "exec", "--user", "root", "mh-server-1", "chmod", "0666", "/home/deploy/.ssh/authorized_keys"],
            check=True,
        )

    def setup_three_server_forwarding(self) -> None:
        """
        Sets up the MINIMAL 3-server topology:
        client -> server1 -> server2.
        Fault: AllowTcpForwarding no on server1.
        """
        subprocess.run([str(self.lab_dir / "start.sh")], cwd=self.lab_dir, stdout=subprocess.DEVNULL, check=True)
        subprocess.run(
            ["sudo", "docker", "stop", "mh-server-4", "mh-server-5", "mh-server-6", "mh-server-7", "mh-server-8"],
            stdout=subprocess.DEVNULL,
            check=True,
        )
        # Connect server2 directly to mh-1-3 so server1 can reach server2
        subprocess.run(
            ["sudo", "docker", "network", "connect", "--ip", "10.201.13.4", "--alias", "server2", "mh-1-3", "mh-server-2"],
            stdout=subprocess.DEVNULL,
            check=True,
        )

        cfg = """Host *
    User deploy
    IdentityFile /home/deploy/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ConnectTimeout 4
    LogLevel ERROR

Host server1
    HostName server1

Host server2
    HostName server2
    ProxyJump server1

Host server3
    HostName server3
    ProxyJump server1
"""
        (self.lab_dir / "client" / ".ssh" / "config").write_text(cfg, encoding="utf-8")
        # Injected fault on hop1 (server1):
        subprocess.run(
            ["sudo", "docker", "exec", "mh-server-1", "sh", "-c", 'printf "\nAllowTcpForwarding no\n" >> /etc/ssh/sshd_config'],
            check=True,
        )
        subprocess.run(["sudo", "docker", "exec", "--user", "root", "mh-server-1", "kill", "-HUP", "1"], check=True)

    def run_eval_trial(
        self,
        agent_type: Literal["openai_luna", "gemini_argon"],
        scenario: Literal["authmode-2server", "authmode-3server", "forwarding-3server", "authmode-4server", "forwarding-4server"],
        max_turns: int = 4,
    ) -> TrialResult:
        trial_id = f"trial_{int(time.time())}_{os.urandom(3).hex()}"
        start_time = time.time()

        # 1. Setup scenario
        target_host: str = "server4"
        allowed_servers: list[str] = ["server1", "server2", "server3", "server4"]
        jump_targets: list[str] = ["server2", "server3", "server4"]
        jump_hosts: list[str] = ["server1", "server2", "server3"]

        if scenario == "authmode-2server":
            self.setup_two_server_authmode()
            target_host = "server1"
            allowed_servers = ["server1"]
            jump_targets = []
            jump_hosts = []
        elif scenario == "authmode-3server":
            self.setup_three_server_authmode()
            target_host = "server2"
            allowed_servers = ["server1", "server2", "server3"]
            jump_targets = ["server2", "server3"]
            jump_hosts = ["server1", "server2", "server3"]
        elif scenario == "forwarding-3server":
            self.setup_three_server_forwarding()
            target_host = "server2"
            allowed_servers = ["server1", "server2", "server3"]
            jump_targets = ["server2", "server3"]
            jump_hosts = ["server1", "server2", "server3"]
        elif scenario == "authmode-4server":
            self.setup_four_server_authmode()
            target_host = "server4"
            allowed_servers = ["server1", "server2", "server3", "server4"]
            jump_targets = ["server2", "server3", "server4"]
            jump_hosts = ["server1", "server2", "server3"]
        elif scenario == "forwarding-4server":
            self.setup_four_server_forwarding()
            target_host = "server4"
            allowed_servers = ["server1", "server2", "server3", "server4"]
            jump_targets = ["server2", "server3", "server4"]
            jump_hosts = ["server1", "server2", "server3"]

        # Initial probe to record baseline failure
        init_probe = self.dispatcher.verify_target(target_host)
        tools = build_tool_inventory(allowed_servers, jump_targets, jump_hosts)

        # Agent Initialization with Canonical Benchmark Prompt
        prompt = (
            f"Use SSH from this client to run hostname on {target_host}. "
            f"If it fails, make at most one read-only diagnostic tool call, "
            f"then choose one minimal reversible SSH fix and verify {target_host}. "
            f"Do not reset containers or replace keys."
        )

        tool_records: list[ToolExecutionRecord] = []
        final_resp = ""
        final_think = ""
        repair_action_summary: Optional[str] = None

        if agent_type == "openai_luna":
            agent: OpenAILunaAgent = OpenAILunaAgent(self.openai_key, model="gpt-6-luna", effort="low")
            history: list[dict[str, Any]] = [
                {"role": "user", "content": [{"type": "input_text", "text": prompt}]}
            ]

            for turn in range(max_turns):
                turn_resp, tool_calls_openai, lat = agent.run_turn(history, tools)

                # Extract reasoning summary if available
                for item in turn_resp.get("output", []):
                    if item.get("type") == "reasoning":
                        final_think += str(item.get("summary", "")) or str(item.get("content", ""))

                if not tool_calls_openai:
                    # Model provided text answer
                    final_resp = turn_resp.get("output_text", "")
                    if not final_resp:
                        for item in turn_resp.get("output", []):
                            if item.get("type") == "message":
                                for c in item.get("content", []):
                                    if c.get("type") in ("output_text", "text"):
                                        final_resp += c.get("text", "")
                    break

                # Append model outputs to conversation history
                history.extend(turn_resp.get("output", []))

                # Dispatch tool calls and append function_call_output
                for fn_name, fn_args, call_id in tool_calls_openai:
                    if fn_name in ("set_proxy_jump", "change_file_mode", "change_sshd_directive", "append_client_public_key"):
                        repair_action_summary = f"{fn_name}({json.dumps(fn_args)})"

                    res = self.dispatcher.dispatch(fn_name, fn_args, allowed_servers)
                    tool_records.append(ToolExecutionRecord(turn, fn_name, fn_args, res, lat))

                    history.append({
                        "type": "function_call_output",
                        "call_id": call_id,
                        "output": json.dumps(res, ensure_ascii=False)
                    })

        elif agent_type == "gemini_argon":
            gemini_agent: GeminiArgonAgent = GeminiArgonAgent(self.gemini_key, model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), thinking_budget=1024)
            gemini_history: list[dict[str, Any]] = [
                {"role": "user", "parts": [{"text": prompt}]}
            ]

            for turn in range(max_turns):
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

                # Handle tool executions
                user_parts: list[dict[str, Any]] = []
                for fn_name, fn_args in tool_calls_gemini:
                    if fn_name in ("set_proxy_jump", "change_file_mode", "change_sshd_directive", "append_client_public_key"):
                        repair_action_summary = f"{fn_name}({json.dumps(fn_args)})"

                    res = self.dispatcher.dispatch(fn_name, fn_args, allowed_servers)
                    tool_records.append(ToolExecutionRecord(turn, fn_name, fn_args, res, lat))
                    user_parts.append({
                        "functionResponse": {
                            "name": fn_name,
                            "response": res
                        }
                    })

                gemini_history.append({"role": "user", "parts": user_parts})

        # Final Verification Check
        verify_res = self.dispatcher.verify_target(target_host)
        success = (verify_res["exit_code"] == 0 and target_host in verify_res["stdout"])

        # Determine Misdiagnosis Category
        misdiag = "CORRECT_MINIMAL_REPAIR" if success else "UNKNOWN_FAILURE"
        if not success:
            if repair_action_summary is None:
                misdiag = "NO_REPAIR_ATTEMPTED"
            elif "set_proxy_jump" in repair_action_summary:
                misdiag = "WRONG_PROXYJUMP_BYPASS"
            elif "append_client_public_key" in repair_action_summary:
                misdiag = "REDUNDANT_KEY_APPEND"
            elif "change_sshd_directive" in repair_action_summary:
                if f'"{target_host}"' in repair_action_summary and target_host != "server1":
                    misdiag = "WRONG_TARGET_MUTATION"
                elif "AllowTcpForwarding" not in repair_action_summary:
                    misdiag = "WRONG_DIRECTIVE_MUTATION"
                else:
                    misdiag = "INEFFECTIVE_MUTATION"
            elif "change_file_mode" in repair_action_summary:
                if f'"{target_host}"' in repair_action_summary and target_host not in ("server1", "server2"):
                    misdiag = "WRONG_TARGET_MUTATION"
                else:
                    misdiag = "INEFFECTIVE_MUTATION"

        duration = round(time.time() - start_time, 2)
        return TrialResult(
            trial_id=trial_id,
            model=agent_type,
            reasoning_tier="low",
            fault_scenario=scenario,
            topology=f"{len(allowed_servers)}-server",
            initial_exit_code=init_probe["exit_code"],
            initial_stderr=init_probe["stderr"],
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

# ==============================================================================
# 8. CLI RUNNER & ENTRYPOINT
# ==============================================================================

def main() -> None:
    lab_dir = Path("/home/agent1/testsshprobs/lab/multihop")
    if not lab_dir.exists():
        # Fallback for local testing
        lab_dir = Path.cwd()

    # Find keys in lab directory or parent directories
    candidate_paths = [
        lab_dir.parent.parent,
        lab_dir.parent,
        lab_dir,
    ]
    openai_key = ""
    gemini_key = ""

    for p in candidate_paths:
        ok = p / "openai.key.txt"
        if ok.exists() and not openai_key:
            openai_key = ok.read_text(encoding="utf-8").strip()
        gk = p / "gemini.key.txt"
        if gk.exists() and not gemini_key:
            gemini_key = gk.read_text(encoding="utf-8").strip()
        legacy_key = p / "key.txt"
        if legacy_key.exists() and not openai_key:
            openai_key = legacy_key.read_text(encoding="utf-8").strip()

    orchestrator = ExperimentOrchestrator(lab_dir, openai_key, gemini_key)

    scenarios: list[Literal["authmode-2server", "authmode-3server", "forwarding-3server", "authmode-4server", "forwarding-4server"]] = [
        "authmode-2server",
        "forwarding-3server",
        "authmode-3server",
        "forwarding-4server",
        "authmode-4server",
    ]
    models: list[Literal["openai_luna", "gemini_argon"]] = ["openai_luna", "gemini_argon"]

    num_repeats = 3  # 3 trials per combination = 30 trials total for empirical failure probability

    print("=====================================================================")
    print("SSH DIAGNOSTIC BENCHMARK: MINIMAL HIGH-MISDIAGNOSIS SUITE")
    print(f"Models: gpt-6-luna (effort=low) vs gemini-4-argon (budget=1024)")
    print(f"Repeats per test: {num_repeats} (Total trials: {len(scenarios) * len(models) * num_repeats})")
    print("=====================================================================")

    results: list[dict[str, Any]] = []

    for sc in scenarios:
        for md in models:
            for rep in range(1, num_repeats + 1):
                print(f"\n[RUNNING] Scenario: {sc:18} | Model: {md:12} | Trial {rep}/{num_repeats} ...", end="", flush=True)
                res = orchestrator.run_eval_trial(md, sc, max_turns=4)
                print(f" -> SUCCESS: {res.task_success:5} | Category: {res.misdiagnosis_category:24} | Action: {res.final_repair_action}")
                results.append(dataclasses.asdict(res))

    out_file = lab_dir / "minimal_high_failure_benchmark_results.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[SAVED] Benchmark traces written to {out_file}")

    # Summary Statistics
    print("\n=====================================================================")
    print("BENCHMARK SUMMARY RESULTS TABLE")
    print("=====================================================================")
    print(f"{'Scenario':<20} | {'Model':<14} | {'Trials':<6} | {'Failures':<8} | {'Misdiag Rate':<12} | {'Top Misdiagnosis Category'}")
    print("-" * 85)

    for sc in scenarios:
        for md in models:
            subset = [r for r in results if r["fault_scenario"] == sc and r["model"] == md]
            total = len(subset)
            fails = sum(1 for r in subset if not r["task_success"])
            rate = (fails / total * 100.0) if total > 0 else 0.0
            categories: dict[str, int] = {}
            for r in subset:
                cat = r["misdiagnosis_category"]
                categories[cat] = categories.get(cat, 0) + 1
            sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)
            top_cat = f"{sorted_cats[0][0]} ({sorted_cats[0][1]}/{total})" if sorted_cats else "N/A"
            print(f"{sc:<20} | {md:<14} | {total:<6} | {fails:<8} | {rate:>5.1f}%      | {top_cat}")

if __name__ == "__main__":
    main()
