---
name: prompt-caching
description: Design, diagnose, and measure prompt-cache reuse for OpenAI or Gemini API workloads, including stable prefixes, tool schemas, cache diagnostics, token accounting, and explicit cache lifetimes.
---

# Prompt caching

Use provider documentation for the selected model and API. Prompt caching is provider- and model-specific; do not apply one provider's thresholds, lifetimes, pricing, or controls to another.

## Preserve a reusable prefix

- Put large, stable instructions, reference material, and tool definitions before request-specific content. Put the changing question, trial identifier, timestamp, or other runtime data at the end.
- Keep the model, service tier, tools and tool order, schemas, output format, reasoning settings, and prior conversation history stable when comparing cache reuse. A change can invalidate the matching prefix from that point onward.
- Keep trial-specific faults and observations out of a reusable shared prefix. Reusing generic instructions or tool schemas does not require reusing a previous conversation or incident context.
- Preserve and append conversation history in multi-turn requests instead of rewriting earlier messages. Do not add filler merely to cross a cache threshold; estimate whether expected reuse justifies the larger prefix and any cache-write/storage cost.
- A cache hit is not guaranteed by stable text alone. Eligibility, routing, retention, token thresholds, explicit breakpoints, and model support vary.

## OpenAI API

- Prompt caching is automatic for supported models. Check the current model documentation for minimum cacheable input, eligible breakpoints, supported retention, cache-read rates, and cache-write rates.
- For GPT-5.6 and later, the current guide documents a 1,024 visible-token minimum, implicit caching by default, explicit breakpoints, and `prompt_cache_options` controls. Do not assume these details apply to every model.
- Keep tool definitions and ordering fixed. When a request needs fewer callable tools, prefer `tool_choice: "none"` or `allowed_tools` where supported instead of removing or reordering schemas.
- To investigate a missed prefix on supported Responses API models, pass a recent completed same-organization response ID as `prompt_cache_options.comparison_response_id`. Read `prompt_cache_diagnostics` and `usage.input_tokens_details`; diagnostics are best-effort and do not themselves load prior conversation content or change caching behavior.
- Record input tokens, cached tokens, cache-write tokens (including lifetime breakdown where returned), output tokens, latency, model, effort, service tier, and realized price. Cache-write tokens are an input billing category at the model's cache-write rate, not a separate fee to add a second time.
- Extra baseline or retry requests are billed normally. Do not make extra calls solely to obtain diagnostics unless they are useful to the task.

## Gemini API

- Check current model support and token thresholds. Gemini implicit caching and explicit cached-content resources are different mechanisms; implicit reuse is not guaranteed.
- Use explicit context caching only when the same substantial context will be reused enough to justify cache creation and storage charges. Reference the cache resource by name, choose a TTL based on expected reuse, and delete it when appropriate.
- Count cache token usage, cached input, non-cached input, output, and storage duration using current Gemini usage metadata and pricing. Do not describe explicit caching as free or assume every later request avoids input charges.
- Model support changes over time. Current Gemini documentation may exclude newer model families from explicit caching, so verify before implementing.

## Evaluate a caching change

1. Capture a baseline with the current request shape and record model, settings, stable prefix, dynamic suffix, tool schemas, token usage, cache diagnostics, latency, and cost.
2. Change one cache-relevant property at a time, such as moving dynamic fields to the suffix or stabilizing tool order.
3. Compare requests against a recent, valid baseline and inspect both diagnostic reason and actual usage. A diagnostic `cache_hit` does not mean all current input was cached; only usage counts show reused tokens.
4. Repeat enough representative requests to include cold starts, warm reuse, and realistic idle intervals. Separate intended cache writes from misses and calculate net cost at current model rates.
5. Keep behavioral evaluation independent from cache evaluation. If test cases must have fresh context, reuse only generic stable prefixes; do not pass prior incident messages, tool results, or response IDs as conversation history.

## Primary references

- [OpenAI prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching)
- [OpenAI prompt cache diagnostics](https://developers.openai.com/api/docs/guides/prompt-caching/diagnostics)
- [OpenAI Responses API reference](https://developers.openai.com/api/reference/resources/responses/methods/create)
- [Gemini context caching](https://ai.google.dev/gemini-api/docs/generate-content/caching)
- [Gemini optimization guide](https://ai.google.dev/gemini-api/docs/optimization)
- [Google Gen AI Python SDK cache methods](https://googleapis.github.io/python-genai/)
