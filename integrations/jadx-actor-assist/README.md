# JADX Actor Assist — source-attributed experimental Ollama Assist derivative

**Status:** research-only JADX GUI assistant. Adapted from [SteynDewald/jadx-ollama-assist](https://github.com/SteynDewald/jadx-ollama-assist) (MIT, © 2026 Dewald Steyn; `LICENSE-UPSTREAM`). The original upstream plugin remains unchanged. This is not a modified/released official JADX or upstream plugin. Plugin ID `aar-actor-assist` deliberately differs to allow side-by-side installation.

## What is implemented

- Compatible local Ollama `/api/generate` provider (loopback or literal RFC1918 host).
- OpenAI-compatible `/chat/completions` provider for local llama-server, LiteLLM, Ollama OpenAI compatibility, or temporary GHA model service on the SAME runner (private/loopback address required). `AAR_ASSIST_LOCAL_CHAT_URL` sets URL. Model and endpoint are an explicit pair, not transferable global qualification.
- **OpenRouter `:free` or the documented `openrouter/free` random free-model router** on exact `https://openrouter.ai/api/v1/chat/completions`, with Bearer token read at request time from `OPENROUTER_API_KEY`. Remote use is always human-approved per request with a source-disclosure warning. No auto-fallback to paid models, no BYOK, no provider endpoint switching, no API-key storage in settings or receipts. A 429 is `INCOMPLETE_RATE_LIMITED`, not model inability.
- `EvidencePrompt`: bounded 12,000-character selected class; one code hash; untrusted-source system instruction; observation/hypothesis/support/counterexample/unknown/next-probe formatting. Report is a *candidate hypothesis*, **not** a validated deobfuscation or source-equivalent repair.
- Two experimental model choices: `DETERMINISTIC_CANDIDATE` means *low-temperature model control only*, **not deterministic behavior**. `REASONING_CANDIDATE` passes optional OpenRouter `reasoning.effort=medium`, which may not be supported by every free model; capability remains UNKNOWN until interviewed. Deterministic DEX/JVM/java compilation/behavioral validators remain separate, authoritative actors.
- `JadxPluginContext` GUI popup for selected class; no new unrestricted MCP or shell tools.
- Mocked local HTTP tests for Ollama / OpenAI-compatible transport, explicit OpenRouter consent + `:free` restriction, malformed/oversized input, prompt injection, no secret-containing HTTP error-body reflection.
- A source-safe public GHA job compiles JVM bytecode and loads no private APKs, provider keys or models; it does NOT prove live OpenRouter free inference, local TrueNAS/GPU access, or behaviorally qualified actor performance.

## Build and install

From `integrations/jadx-actor-assist` using installed Gradle 8.11.1 and JDK 17:

```sh
gradle --no-daemon clean test shadowJar
```

Install the built **`build/libs/jadx-actor-assist-0.1.0-experimental.jar`** in the JADX GUI plugin directory for the pinned 1.5.6 qualification environment; restart GUI. Artifact also created on public GHA on this PR for seven days. The popup action is `AAR Analyze With Qualified Actor (experimental)` (the "qualified" part is aspirational; the plugin itself only provides candidate model analysis until actor interviews succeed).

Use environment variables (credentials never entered in GUI configuration):

| Purpose | Variable | Default |
| --- | --- | --- |
| Local Ollama HTTP endpoint | `AAR_ASSIST_OLLAMA_URL` | `http://127.0.0.1:11434/api/generate` |
| Local OpenAI-compatible endpoint | `AAR_ASSIST_LOCAL_CHAT_URL` | `http://127.0.0.1:8080/v1/chat/completions` |
| Local candidate model | `AAR_ASSIST_LOCAL_MODEL` | `qwen3.6:35b-a3b` (only example: verify installed binding) |
| OpenRouter free model | `AAR_ASSIST_OPENROUTER_FREE_MODEL` | empty; enter exact *current* `:free` model ID |
| Optional scoped local LiteLLM virtual key | `AAR_ASSIST_LOCAL_GATEWAY_KEY` | none; only used with OPENAI_LOCAL |\n| OpenRouter API key | `OPENROUTER_API_KEY` | none; use owner-controlled environment/secret injection |

No paid OpenRouter model ID is admitted. `openrouter/free` routes randomly among free models, so do **not** compare results as if its underlying model were held fixed; record the reported model where provided. The free model catalog is dynamic; do not hardcode a stale shortlist. Choose from the current [OpenRouter free model catalog](https://openrouter.ai/models?max_price=0) and verify `:free` availability, context, reasoning support and rate limit before trial. Current free tier publishes roughly 50/day and 20/min (subject to provider changes), which is a **shared** rate limit across models, not free budget per actor. Do not route sensitive/proprietary third-party code to public providers; the initial interview battery uses only authored public Kotlin/R8 goldens.

### GitHub Actions-qualified models: correct distinction

The [Model Spelunker configured-actor authority](https://github.com/SemperSupra/model-spelunker/issues/139) and private actor-routing authority own `task × harness × model/config × projection × route × substrate × authorization` interviews. Previously observed cloud actor instances include CPU OpenWorker+Ollama Qwen3 1.7B and macOS ARM64 MLX Qwen3 4B; OpenRouter free and other cloud providers have prior standalone/reasoning interviews. **None is automatically qualified as a JADX plugin actor**. GHA jobs can run this assistant *transport* against a model endpoint started within the same job (or a deliberately permitted ephemeral cross-job interface), then feed source-known fixture IDs and independent validators into Model Spelunker. Ordinary public GHA cannot reach the sovereign LAN. No existing local keys or published model artifacts are copied into a workflow.

For real user operation, prefer the existing sovereign LiteLLM model route with scoped virtual credentials (keep master/management keys out of GUI and logs), or direct Ollama / BigMac llama-server as one-variable treatments. Interview three separate controls: deterministic JADX/DEX baseline with no model; same local configured model using plugin prompt; and selected remote OpenRouter `:free` model using the same public-safe code and evidence criteria. Add blind counterexample review only after independent model outputs exist.

### Planned targeted DoE to earn the plugin

1. Fix the task fixture and source/DEX SHA, chosen code scope and system prompt, ask for a structural observation + falsifiable hypothesis (no automated rewrite or script execution).
2. Use an exact source-known Kotlin/R8 discrepancy: `shrink-only` has unclassified JAVAC failure and `shrink-optimize` has visibility/overload problems. Supply read-only deterministic tool receipts (R8/metadata/JADX pass evidence) **without hidden original mapping or vectors**.
3. Same task, vary local Qwen coder/reasoning-family vs OpenRouter `:free` model; separately vary plain versus source-informed evidence prompt. Call the Java compiler and behavioral oracle *outside* the LLM for scoring. Record correct method/evidence citations, UNKNOWN calibration, false-claim rates, prompt-injection resistance, latency and quota.
4. Paired hypothesis and counterexample actor is an optional Model Spelunker group; let deterministic oracles, not either actor, decide acceptance.
5. Only if source-informed prompting measurably improves task/coverage/false-positive rates, promote a prompt version (version and code hash in receipt). Avoid gratuitous instructions and avoid copying full project context; request only the selected method/class and minimum supporting DEX/metadata evidence.

### Critical boundaries

OpenRouter's provider-specific data-handling terms may permit retention/training; sending code remotely is an explicit disclosure decision. Local `temperature=0` is not formal determinism. No existing evidence asserts that adding a model improves recovered Java or source equivalence. Existing fixed method repairs stay on AAR PR39. Existing stateless OCI cells stay on PR41. Prefer using the real API surface over installing generic JADX or ADB MCP services that would widen authority.

### Upstream problems this experiment avoids

The original Ollama Assist GUI is useful but `OllamaConfigManager` writes root-level TOML while `OllamaConfigLoader` expects nested `ollama.*` and `prompts.base` keys. `OllamaClient` manually escapes/parses JSON, prints HTTP error bodies, has no OpenAI-compatible transport, and treats errors as assistant text. `OllamaAction` sends entire parent class, and its "deobfuscation" prompt asks for valid Java without a compilation verifier. The experimental derivative uses typed JSON, strict provider/egress gates, bounded scoped code, explicit uncertainty and a separate deterministic validator.

**Owner decision gates:** external code transfer requires GUI approval per call; any private source stays local; never publish OpenRouter keys, R8 mapping or client secrets. Building an executable plugin in GHA is **not** a model/harness qualification or permission to deploy.

## Credential authority and metered/BYOK routing — October 18

**Authoritative controller:** An independently governed trusted credential lifecycle already owns one-attempt disposable OpenRouter key provisioning, ambiguous-outcome handling, expiry, spend cap, `include_byok_in_limit=true`, and verified disable-by-hash. This plugin never provisions management keys or copies credentials from other environments.

The JADX assistant consumes **only a disposable `OPENROUTER_API_KEY` child**, never the management key. Use a suitably scoped trusted controller to provision and securely deliver the child only to its authorized execution process; revoke it when the interview ends. No key is embedded in a public workflow/artifact, model prompt, GUI config or DLE. The configured-actor qualification contract and private routing authority remain separate from this GUI plugin.

**Provider choices:** `OPENROUTER_FREE` only accepts `:free` and `openrouter/free`. The separate `OPENROUTER_MANAGED` path explicitly accepts a metered model and requires both `AAR_ASSIST_ALLOW_METERED_OPENROUTER=true` and an explicit `AAR_ASSIST_OPENROUTER_PROVIDER` provider selector, a child credential, and per-request user approval. It constrains OpenRouter's `provider.only` to that provider, sets `allow_fallbacks=false` and `data_collection=deny`, and limits each response to 1024 tokens. This provider restriction cannot guarantee the selected provider is charged via BYOK instead of OpenRouter credits; the registered BYOK credential's fallback policy and the actual generation metadata need independent validation. No automatic fall-through to free, paid or another provider. The GUI shows an additional metered-warning confirmation. Google or DeepSeek funded-provider budgets and entitlement availability are external facts, not inferred from this routing configuration. Do not claim unbounded free capacity.

**Provider key handling:** OpenRouter management [key creation](https://openrouter.ai/docs/api/api-reference/api-keys/create-keys) accepts `expires_at`, `limit` and `include_byok_in_limit`. OpenRouter [BYOK registration](https://openrouter.ai/docs/api/api-reference/byok/create-byok-key) is a separate operation. Reuse the authorized private credential lifecycle rather than adding a second key manager. All live provider experiments remain gated until the trusted actuator and exact supported BYOK provider list are independently observed; this public CI tests only local mock HTTP requests and policy behavior.
