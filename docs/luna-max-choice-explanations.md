# Luna 6 max effort: explanations behind SSH choices

This note selects examples from the reproducible four-server `authmode` scenario run with `gpt-6-luna` at `reasoning.effort=max`. It records the agents’ own final-answer explanations (the requested `thinking` field was a brief, user-facing rationale, not hidden model state), then compares those explanations with the observed tool results.

## Scenario and outcome snapshot

The task was to run `hostname` on `server4`, make at most one read-only diagnostic call after an initial failure, then choose one minimal reversible SSH fix and verify. The seeded fault was an overly permissive mode on server2’s `/home/deploy/.ssh/authorized_keys`. OpenSSH refused authentication there because of bad ownership or modes; setting the file to `0600` fixed the route without changing key contents.

Among the seven runs with a completed final answer, two applied the mode fix and verified `server4`; four changed `ProxyJump` and failed verification; and one tried to append a key that was already present, which made no change. One additional trace ended in an API timeout after the no-op append and has no final explanation to assess. This is a small illustrative sample, not a stable probability estimate.

## Wrong choice: changing the route instead of fixing the rejected authentication

### Example A — switch to a hop that had authenticated

Trace: `lab/multihop/trial_python_responses_1793051609_fab12c96.json`

The agent’s explanation:

> “Bypassing server2 via the already-authenticated server3 seemed a plausible, minimal fix; changing one ProxyJump line is reversible.”

What happened: the initial verbose trace did show successful authentication through earlier hops and rejection at server2. The agent then changed server4’s `ProxyJump` from server2 to server3. The retry returned `stdio forwarding failed`; it never ran `hostname` successfully.

Assessment: The rationale correctly identifies the failing hop and values reversibility, but it infers that server3 can serve as a direct jump to server4 without evidence that the network path allows it. The authentication rejection was a server-side clue, and the route edit did not address the credential file’s permissions. A read-only server log inspection would have been more diagnostic within the stated limit.

### Example B — the effective route is mistaken for the cause

Trace: `lab/multihop/trial_python_responses_1793052052_698db094.json`

The agent’s explanation:

> “The configured jump route was suspect, so I changed only that alias’s `ProxyJump` to server1; this was a minimal, reversible config change, not a confirmed topology diagnosis.”

What happened: the read-only call confirmed the effective `ProxyJump` was server2. The agent changed it to server1. Verification again returned `stdio forwarding failed`.

Assessment: The agent explicitly acknowledges that the route theory was unconfirmed, which is good calibration. But the diagnostic only established which route was configured; it did not establish that the route was wrong. The original error named `server2` authentication, so a route change was weakly supported and failed to reach the target.

### Example C — same inference, with a more explicit limitation

Trace: `lab/multihop/trial_python_responses_1793051871_1e88ceed.json`

The agent’s explanation:

> “switching to server1 was a minimal, reversible way to bypass that failing jump.”

The agent then noted that verification failed with `stdio forwarding failed` and that it did not obtain the hostname.

Assessment: Reporting the failed verification plainly is useful. The underlying choice still treats the jump host as the cause when the observed `Permission denied (publickey)` says authentication at that host failed. “Minimal” describes the size of the edit, but does not establish that the edit is relevant to the fault.

## Low-importance choice: repeat a key that is already present

Trace: `lab/multihop/trial_python_responses_1793051469_9fc9d135.json`

The agent’s explanation:

> “an idempotent append was the least invasive potential authentication fix, but it made no change.”

The read-only inspection showed an authorized key entry. The append tool then reported `already_present: true`, identical before-and-after hashes, and preservation of the previous bytes. The next SSH attempt failed with the same server2 public-key denial.

Assessment: This was non-destructive and the agent correctly recognized and reported the no-op. It was low value because seeing an entry in `authorized_keys` does not check whether sshd accepts the file’s ownership and mode. The unchanged hash should have ended that line of inquiry; in this run the agent appropriately made no further speculative changes.

## Right choice: follow the server log and change only the implicated mode

### Example D — explicit evidence, minimal fix, successful verification

Trace: `lab/multihop/trial_python_responses_1793051657_f91d1dbd.json`

The agent’s explanation:

> “the first SSH attempt was denied at server2, whose log reported bad ownership or modes for `/home/deploy/.ssh/authorized_keys`.”
>
> “changing only that file’s mode to `0600` was a minimal, reversible permissions fix supported by the log; the key contents were left unchanged.”

The tool trace confirms the log message, then a successful `change_file_mode` call to `0600`, followed by a successful connection whose stdout was `server4`.

Assessment: This is the strongest diagnosis in the sample. It ties the repair to a direct server-side error, scopes the change to the implicated file, preserves key material, and verifies the requested outcome. The two successful mode-fix runs share this pattern.

## Takeaways from these explanations

- “Minimal” and “reversible” are useful constraints, but they do not make a weakly supported fix diagnostically sound.
- A present public key does not prove sshd can read and accept `authorized_keys`; server logs can distinguish file-policy rejection from a missing-key problem.
- Verification language matters: the successful examples report the actual target hostname, while the failed route-change examples correctly say the target was not reached.
- The short `thinking` explanations are helpful because they separate observations from inferences. In the route-change cases, that separation makes the unsupported inference visible.

## Source traces

The examples above are drawn from the JSON traces in `lab/multihop/`:

- `trial_python_responses_1793051469_9fc9d135.json` — already-present key append, no change.
- `trial_python_responses_1793051609_fab12c96.json` — ProxyJump to server3, failed verification.
- `trial_python_responses_1793051657_f91d1dbd.json` — mode `0600`, successful verification.
- `trial_python_responses_1793051871_1e88ceed.json` — ProxyJump to server1, failed verification.
- `trial_python_responses_1793052052_698db094.json` — ProxyJump to server1, failed verification.

