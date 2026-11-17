# ADR-0006: Send an API key to a custom AI endpoint only when one is named

## Status

Accepted

## Date

2026-11-17

## Context

[ADR-0005](0005-send-ai-analysis-to-a-configurable-openai-compatible-endpoint.md) made the AI endpoint configurable. Its settings table gives `ai_api_key_env` the default `OPENAI_API_KEY` whatever `ai_base_url` is set to.

Running the implementation against a real `.env` showed two problems with that default:

- **The OpenAI key leaks to other providers.** Setting only `ai_base_url: https://openrouter.ai/api/v1` sends the operator's OpenAI key to OpenRouter. Any endpoint in `ai_base_url` receives it, including a mistyped or untrusted one.
- **Local endpoints are refused.** ADR-0005 refuses to send a key over plain HTTP. Most operators keep `OPENAI_API_KEY` in `.env`, so `ai_base_url: http://localhost:11434/v1` for Ollama fails until they set `ai_api_key_env` to some unset variable.

## Decision Drivers

- A key goes only to the endpoint it was issued for, unless the operator says otherwise.
- Pointing `ai_base_url` at a local model is a one-line change.
- The OpenAI default from ADR-0005 keeps working without a config change.

## Options Considered

### Option 1: Keep ADR-0005's default and warn in the README

- **Good:** No change to the accepted design.
- **Bad:** Operators who miss the warning hand their OpenAI key to another provider. Local endpoints need a workaround setting.

### Option 2: With a custom endpoint, send a key only when `ai_api_key_env` is set

`ai_api_key_env` defaults to `OPENAI_API_KEY` only when `ai_base_url` is not set. With `ai_base_url` set, no key is sent unless `ai_api_key_env` names one.

- **Good:** No key reaches an endpoint it wasn't named for. Local endpoints work with `ai_base_url` alone.
- **Bad:** The default of one setting depends on another, which the README must explain.

## Decision

We will use **Option 2**. It amends the `ai_api_key_env` default and the key rules of ADR-0005; everything else in ADR-0005 stands.

| `ai_base_url` | `ai_api_key_env` | Key sent |
|---|---|---|
| not set | not set | `OPENAI_API_KEY`; analysis is skipped if it is unset |
| not set | set | that variable; skipped if it is unset |
| set | not set | none (a fixed placeholder, which the SDK requires) |
| set | set | that variable; skipped if it is unset; refused if `ai_base_url` uses `http://` |

A named variable that is unset skips analysis rather than sending no key, because the operator said the endpoint needs one.

## Consequences

### Positive

- The OpenAI key can't reach another provider by accident.
- `ai_base_url: http://localhost:11434/v1` is enough to use a local Ollama.

### Negative / Trade-offs

- An OpenRouter user who forgets `ai_api_key_env` gets an authentication error from OpenRouter, returned as the analysis text, rather than a working request.

### Risks

- None beyond those of ADR-0005.

## Links

- Amends: [ADR-0005](0005-send-ai-analysis-to-a-configurable-openai-compatible-endpoint.md)
- Roadmap item A2 (`ROADMAP.md`, Audit Remediation, Phase 6)
