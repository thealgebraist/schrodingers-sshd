# Multi-hop SSH diagnosis lab

The lab runs eight Debian SSH server containers and one SSH client on eight internal Docker bridge networks. The client can reach Server 1 directly. The configured chain is:

- `server2`: client → Server 1 → Server 3 → Server 2
- `server8`: client → Server 1 → Server 3 → Server 2 → Server 4 → Server 5 → Server 6 → Server 7 → Server 8

The network links are `mh-client-1`, `mh-1-3`, `mh-3-2`, `mh-2-4`, `mh-4-5`, `mh-5-6`, `mh-6-7`, and `mh-7-8`. All are internal bridges. `./lab/multihop/start.sh` recreates the lab and restores the client SSH config and private-key mode to the saved baseline. `./lab/multihop/stop.sh` removes only lab containers and networks.

## Trial isolation

Each Responses API trial starts a new Python process and new request sequence with `store=false`; it sends no `previous_response_id` or prior trial transcript. Tool-call history exists only within that one trial. Before each trial, the operator recreates the containers, which clears server state and logs, and restores the client config and key mode. Results are saved in `trial_python_responses_*.json` outside model context. Each result includes every request body and raw API response, timestamps, latency, HTTP status and request ID, usage and response metadata, output items, reasoning summary/encrypted reasoning fields returned by the API, and full tool inputs and outputs. Authorization headers and the API key are never written to the trace. SSH command outputs are not clipped. Codex task-model trials use a new thread per run; this runner cannot expose their internal API traces.

The request asks for `reasoning.summary: "auto"` and includes `reasoning.encrypted_content`. OpenAI does not expose raw private reasoning tokens; summaries are the supported readable reasoning artifact, while encrypted reasoning content is opaque and may be retained for API workflows that support it. See the [reasoning guide](https://developers.openai.com/api/docs/guides/reasoning).

## Four-server misdiagnosis batch

`prepare_four_server_trial.sh` resets the environment and leaves four running servers on the route `client → server1 → server3 → server2 → server4`. It supports two faults on Server 2: `SSH_LAB_FAULT=forwarding` disables TCP forwarding while preserving remote shell access; `SSH_LAB_FAULT=authmode` makes `authorized_keys` world-writable so OpenSSH `StrictModes` rejects the otherwise valid key. The API runner only exposes aliases `server1` through `server4`, and asks for a JSON `response` plus a concise evidence-linked `thinking` explanation. The latter means an explanation in the model's own words, not private hidden chain-of-thought. Each run must be preceded by the preparation script so server state and logs are fresh.

For `authmode`, the prompt `Use SSH from this client to run hostname on server4. If it fails, make at most one read-only diagnostic tool call, then choose one minimal reversible SSH fix and verify server4. Do not reset containers or replace keys.` produced 20 fresh trials. None restored access: 18 changed server4's `ProxyJump` to bypass server2, which is still on the network path, and 2 attempted ineffective key-related actions without changing the mode. Thus this sample had an 18/20 (90%) wrong-repair rate and 20/20 task-failure rate. The traces show the tool observed public-key rejection at server2, while the injected root cause was file mode `0666`; the correct repair is changing only that file to `0600`. Treat these as results for this exact prompt, model, topology, and fault—not as a general SSH-competence rate. The full request/response and tool traces are retained per run.

The model receives only an SSH task prompt. It can attempt any configured SSH alias, inspect effective client options, the client config, Docker network attachments, server logs, server config, authorized-key entries, and file metadata. Repair tools are restricted to narrow SSH changes; they validate/reload daemon config when needed, preserve unrelated bytes, and cannot recreate containers or delete data.

## Diagnostic design

A serial SSH route is a pass-chain: a remote command succeeds only if every required earlier hop succeeds. If the only probes are `server2` (depth 3) and `server8` (depth 8), then `server2=success, server8=failure` leaves several intermediate hops observationally possible. In the single-fault test family, Server 6 has forwarding disabled; a correct diagnosis requires locating that hop instead of guessing from the final alias or its configured jump host.

The prompt that produced the current misdiagnosis rate was:

> Connect to server2 and server8. If either fails, apply the most likely single SSH fix based on at most one diagnostic call, then verify both.

## Results

See `trials.json` and the per-run JSON files for evidence. On the eight-server topology:

- Clean control runs connected to both targets without changes.
- A normal diagnostic prompt correctly found and fixed `AllowTcpForwarding no` on Server 6.
- A Server 2 forced-command restriction produced a non-monotone outcome: the `hostname` command failed on Server 2 while Server 8 still worked through it. The model found and removed only that key option.
- With the same Server 6 fault but a prompt limiting the model to one diagnostic call and asking it to choose the most likely single fix, it made the wrong change in 4 of 6 fresh runs (66.7%). Wrong repairs changed Server 8's `ProxyJump` or enabled forwarding on Server 7; none fixed the fault. In the other two runs, it inspected Server 6's config and repaired it correctly.
- Under that same prompt, the fault was also placed once on Server 4, once on Server 5, and once on Server 7. The model changed Server 7 in both the Server 4 and Server 5 cases, then correctly changed Server 7 in its control case. Across this deliberately weighted 9-run batch, 6 fixes were wrong (66.7%).
- A second fault family used Server 6 `authorized_keys` mode `0666`. Under the constrained prompt, all 4 runs failed to repair it: two tried to append a key that was already present, and two changed Server 8's `ProxyJump`. With the full diagnostic prompt, the model checked file metadata, changed only the mode to `0600`, and restored both routes. A `0644` negative control correctly passed because the file was readable but not writable by other users.

These are initial, small samples for two fault families, not a general error-rate estimate. Each run had fresh request state and was preceded by a full container/log reset.

The current reset script restores the baseline client route: Server 2 jumps through Server 3; Server 8 follows the full chain through Server 7. Both target routes are checked after reset by an operator before using the lab.
