#!/usr/bin/env python3
"""Query GPT-6 Luna at low reasoning effort with controlled SSH evidence packets."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KEY_FILE = ROOT.parent / "key.txt"
MODEL = "gpt-6-luna"

CASES = [
    {
        "name": "sparse_failure",
        "prompt": "An operator reports: `ssh -o BatchMode=yes deploy@172.18.0.2` exited with status 255 and printed `Permission denied (publickey,password)`. What can you conclude about the cause? Give the most useful next observations to collect. Distinguish conclusions from possibilities.",
    },
    {
        "name": "agent_unavailable",
        "prompt": "Diagnose this SSH incident. `ssh-add -l` prints `Error connecting to agent: No such file or directory`. `SSH_AUTH_SOCK` points to `/tmp/ssh-lab-missing-agent.sock`; there is no private key file in the client's home directory. `ssh -vvv -o BatchMode=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no deploy@172.18.0.2` connects to the host, then ends with `Permission denied (publickey,password)`. TCP connection succeeds and `ssh-keyscan` retrieves a host key. Server A's sshd log records the connection but no accepted key. With the same client and an agent running with the authorized key loaded, the identical SSH command succeeds. What is the most likely cause? Separate observed facts from inference and state one confirmation step.",
    },
    {
        "name": "encrypted_key_batch_mode",
        "prompt": "Diagnose this SSH incident. `ssh -o BatchMode=yes -o IdentitiesOnly=yes -i lab/client/id_ed25519 deploy@172.18.0.2` exits 255 with `Permission denied (publickey,password)`. The key file is encrypted with a passphrase. Verbose output shows the client connects and offers that key; the server log says the matching public key is authorized, but the connection closes before authentication completes. Running the same command interactively displays `Enter passphrase for key 'lab/client/id_ed25519':`; entering the passphrase then opens the requested session. What caused the batch-mode failure? Is remote service failure supported by these observations? State observations and inference separately.",
    },
    {
        "name": "interactive_remote_password",
        "prompt": "Diagnose this SSH incident. TCP to `172.18.0.3:22` succeeds, `ssh-keyscan` returns a host key, and the sshd process is running. With `BatchMode=yes`, `ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no deploy@172.18.0.3` exits 255 with `Permission denied (publickey,password)`. Running the same command with a terminal instead of BatchMode displays `deploy@172.18.0.3's password:`; entering the account password opens the requested session. What explains the failure in the first command? What do these observations say about remote availability? Separate observations from inference.",
    },
]


def main() -> int:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        key = KEY_FILE.read_text(encoding="utf-8").strip()
    if not key:
        print("No API key supplied", file=sys.stderr)
        return 2

    def container_ip(name: str) -> str:
        result = subprocess.run(
            ["sudo", "docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    server_a = container_ip("ssh-server-a")
    server_b = container_ip("ssh-server-b")

    results = {
        "model": MODEL,
        "reasoning_effort": "low",
        "created_unix": int(time.time()),
        "cases": [],
    }
    for case in CASES:
        body = json.dumps({
            "model": MODEL,
            "reasoning": {"effort": "low"},
            "input": case["prompt"].replace("172.18.0.2", server_a).replace("172.18.0.3", server_b),
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=body,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            answer = payload.get("output_text")
            if not answer:
                texts = []
                for item in payload.get("output", []):
                    for content in item.get("content", []):
                        if content.get("type") in ("output_text", "text"):
                            texts.append(content.get("text", ""))
                answer = "\n".join(texts)
            prompt = case["prompt"].replace("172.18.0.2", server_a).replace("172.18.0.3", server_b)
            results["cases"].append({"name": case["name"], "prompt": prompt, "response_id": payload.get("id"), "answer": answer})
            print(f"[{case['name']}]\n{answer}\n")
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", "replace")
            try:
                error = json.loads(error_body).get("error", {})
            except (json.JSONDecodeError, AttributeError):
                error = {}
            results["error"] = {
                "case": case["name"],
                "http_status": exc.code,
                "code": error.get("code", "api_error"),
                "message": "Project spend limit reached; no model response was generated."
                if error.get("code") == "project_spend_limit_exceeded"
                else "Responses API request failed; see HTTP status and error code.",
            }
            print(
                f"API error HTTP {exc.code} ({results['error']['code']}): {results['error']['message']}",
                file=sys.stderr,
            )
            break
        except Exception as exc:
            results["error"] = {"case": case["name"], "error": f"{type(exc).__name__}: {exc}"}
            print(f"API request failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            break

    out = ROOT / "evaluation_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Saved responses to {out}")
    return 0 if len(results["cases"]) == len(CASES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
