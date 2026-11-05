# Prompt-cache diagnostics for SSH evaluation agents

## What changed

The API runners now request prompt-cache diagnostics on every follow-up turn in the same trial. Each request compares against the immediately preceding response using `prompt_cache_options.comparison_response_id`. The first request has no comparison baseline.

The runners continue to send the full conversation input themselves, with `store=false`; they do not send `previous_response_id`. A comparison ID requests cache diagnostics only—it does not load the earlier response content. Comparisons never cross trial boundaries, preserving the no-memory-between-tests rule. No `prompt_cache_key` is supplied.

Each successful API trace retains the raw response and adds easy-to-read fields for `prompt_cache_diagnostics`, `usage`, actual `cached_tokens`, `cache_write_tokens`, and returned `service_tier`. A per-run `prompt_cache_summary` totals input, cached input, cache-write, and output tokens; counts diagnostic outcomes and cache-miss reasons; and reports cached input as a fraction of input tokens. API failures without usage are counted as requests but do not contribute fabricated token data.

The shared four-server Luna runner and both historical DBC runners were updated. A dedicated eight-server Luna-low runner was added at `lab/multihop/python_agent_luna_low_8server_once.py`; its default task prompt contains only a command, intended result, and reported SSH error. The 64-server C23/Souffle runner at `benchmarks/ssh-complex/luna_agent.py` now uses the same per-trial comparison pattern. None of these implementations issues an extra diagnostic API call.

## Analysis of existing Luna-low traces

A local aggregation of unique `gpt-6-luna` JSON traces found 93 run records. Fifty-two had usage data, comprising 274 API requests:

| Metric | Total |
| --- | ---: |
| Input tokens | 2,469,863 |
| Cached input tokens | 2,054,123 |
| Cached share of input | 83.17% |
| Cache-write tokens | 414,788 |
| Output tokens | 123,680 |

These prior traces did not request `prompt_cache_diagnostics`, so they show how much input was reported as cached, but cannot explain individual cache misses. The totals also count the growing conversation input on every API turn. They are not unique prompt size or a direct dollar estimate.

This indicates that prompt caching was already reusing a substantial amount of the repeated tool and conversation prefix in these Luna runs. The new diagnostic field will help identify why reuse is unexpectedly low (for example, a changed tool schema, model, settings, or earlier input). It does not itself improve reuse or lower the price. Actual reuse should be read from `usage.input_tokens_details.cached_tokens`; the API's ordinary billing rules still apply to each request.

## Cost and privacy implications

OpenAI documents prompt-cache diagnostics as having no additional charge and not counting separately toward rate limits. The comparison is attached to an existing Responses request, so this implementation adds no baseline/retry request. Any separately launched model run remains normally billable. Diagnostics are documented as compatible with Zero Data Retention; the comparison ID does not retrieve earlier response content.

At the time this instrumentation was first written, the project spend limit blocked repeat requests before model execution, so that initial change had no live API validation. The user later confirmed the limit problem was fixed. The two latest 64-server trial traces predate the cache-diagnostics addition; future traces from that runner will record comparison diagnostics and cache-miss reasons.

## Reproduce and inspect

Run the Luna-low eight-server agent from the lab workspace with a short prompt such as:

```sh
SSH_AGENT_REASONING_EFFORT=low \
SSH_AGENT_PROMPT='Run `ssh server8 hostname` to retrieve the hostname of server8. It failed with `kex_exchange_identification: Connection closed by remote host`. Diagnose the SSH issue, restore access, and verify the command.' \
python3 lab/multihop/python_agent_luna_low_8server_once.py
```

For each API turn, inspect `api_traces[*].prompt_cache_diagnostics` and `api_traces[*].usage.input_tokens_details`. The aggregate is saved as `prompt_cache_summary` in each emitted trace. The first response will have no comparison diagnostic; later responses compare only with the preceding response in that trial.

## References

- [Prompt cache diagnostics](https://developers.openai.com/api/docs/guides/prompt-caching/diagnostics)
- [Prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching)
