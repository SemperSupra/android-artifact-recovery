package org.sempersupra.aar.jadx;

import java.net.URI;
import java.util.Objects;

/** Explicit provider/model binding. External inference is never implicit. */
public final class AssistProfile {
    public enum Provider { OLLAMA_LOCAL, OPENAI_LOCAL, OPENROUTER_FREE, OPENROUTER_MANAGED }
    public enum Role { DETERMINISTIC_CANDIDATE, REASONING_CANDIDATE }
    public final Provider provider;
    public final Role role;
    public final String model;
    public final URI endpoint;
    public final double temperature;
    public final String reasoningEffort;

    public AssistProfile(Provider provider, Role role, String model, URI endpoint,
                         double temperature, String reasoningEffort) {
        this.provider = Objects.requireNonNull(provider);
        this.role = Objects.requireNonNull(role);
        this.model = Objects.requireNonNull(model).trim();
        this.endpoint = Objects.requireNonNull(endpoint);
        if (this.model.isEmpty() || this.model.length() > 160 ||
            this.model.contains("\n") || this.model.contains("\r")) {
            throw new IllegalArgumentException("A selected model ID is required");
        }
        if (!Double.isFinite(temperature) || temperature < 0 || temperature > 1) {
            throw new IllegalArgumentException("Invalid temperature");
        }
        this.temperature = temperature;
        this.reasoningEffort = Objects.requireNonNull(reasoningEffort);
        if (!("none".equals(reasoningEffort) || "low".equals(reasoningEffort)
              || "medium".equals(reasoningEffort) || "high".equals(reasoningEffort))) {
            throw new IllegalArgumentException("Reasoning effort must be none/low/medium/high");
        }
        String host = endpoint.getHost();
        if (endpoint.getUserInfo() != null || endpoint.getFragment() != null ||
            endpoint.getQuery() != null || host == null || endpoint.getPort() == 0) {
            throw new IllegalArgumentException("Endpoint may not contain credentials, query or fragment");
        }
        if (provider == Provider.OPENROUTER_FREE || provider == Provider.OPENROUTER_MANAGED) {
            if (!URI.create("https://openrouter.ai/api/v1/chat/completions").equals(endpoint))
                throw new IllegalArgumentException("Use the official OpenRouter HTTPS endpoint");
            boolean free = model.endsWith(":free") || "openrouter/free".equals(model);
            if ((provider == Provider.OPENROUTER_FREE && !free)
                || (provider == Provider.OPENROUTER_MANAGED && free))
                throw new IllegalArgumentException("Free and metered OpenRouter routes may not mix");
        } else {
            String h = host.toLowerCase(java.util.Locale.ROOT);
            boolean loopback = h.equals("localhost") || h.equals("127.0.0.1") || h.equals("::1");
            boolean privateIpv4 = h.matches("10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")
                || h.matches("192\\.168\\.\\d{1,3}\\.\\d{1,3}")
                || h.matches("172\\.(1[6-9]|2[0-9]|3[01])\\.\\d{1,3}\\.\\d{1,3}");
            if (!(loopback || privateIpv4) || !("http".equals(endpoint.getScheme())
                      || "https".equals(endpoint.getScheme()))) {
                throw new IllegalArgumentException("Local inference must use explicit loopback/RFC1918 host");
            }
            String path = endpoint.getPath();
            if (provider == Provider.OLLAMA_LOCAL && !"/api/generate".equals(path)) {
                throw new IllegalArgumentException("Ollama path must be /api/generate");
            }
            if (provider == Provider.OPENAI_LOCAL && !path.endsWith("/chat/completions")) {
                throw new IllegalArgumentException("OpenAI-compatible path must end with /chat/completions");
            }
        }
    }

    public static AssistProfile fromSelection(Provider provider, Role role, String model) {
        String endpoint = (provider == Provider.OPENROUTER_FREE || provider == Provider.OPENROUTER_MANAGED)
            ? "https://openrouter.ai/api/v1/chat/completions"
            : provider == Provider.OLLAMA_LOCAL
                ? System.getenv().getOrDefault("AAR_ASSIST_OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
                : System.getenv().getOrDefault("AAR_ASSIST_LOCAL_CHAT_URL", "http://127.0.0.1:8080/v1/chat/completions");
        return new AssistProfile(provider, role, model, URI.create(endpoint),
            role == Role.DETERMINISTIC_CANDIDATE ? 0 : 0.2,
            role == Role.REASONING_CANDIDATE ? "medium" : "none");
    }
}
