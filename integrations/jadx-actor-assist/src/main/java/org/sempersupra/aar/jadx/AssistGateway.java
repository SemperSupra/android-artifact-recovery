package org.sempersupra.aar.jadx;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** Bounded request transport; no arbitrary tools, fallback models or secret logging. */
public final class AssistGateway {
    public static final class Reply {
        public final String text, model, observedModel, codeSha256, promptVersion;
        public Reply(String text, String model, String observedModel, String codeSha256) {
            this.text=text; this.model=model; this.observedModel=observedModel;
            this.codeSha256=codeSha256;
            this.promptVersion=EvidencePrompt.VERSION;
        }
    }
    private final HttpClient client;
    private final Supplier<String> externalKey;
    private final Supplier<String> localGatewayKey;
    private final Supplier<Boolean> meteredEnabled;
    private final Supplier<String> routingProvider;
    private final Gson gson = new Gson();
    public AssistGateway() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8))
            .followRedirects(HttpClient.Redirect.NEVER).build(),
            () -> System.getenv("OPENROUTER_API_KEY"),
            () -> System.getenv("AAR_ASSIST_LOCAL_GATEWAY_KEY"),
            () -> "true".equals(System.getenv("AAR_ASSIST_ALLOW_METERED_OPENROUTER")),
            () -> System.getenv("AAR_ASSIST_OPENROUTER_PROVIDER"));
    }
    public AssistGateway(HttpClient client, Supplier<String> externalKey) {
        this(client, externalKey, () -> null);
    }
    public AssistGateway(HttpClient client, Supplier<String> externalKey,
                         Supplier<String> localGatewayKey) {
        this(client,externalKey,localGatewayKey,()->false,()->null);
    }
    public AssistGateway(HttpClient client,Supplier<String> externalKey,
                         Supplier<String> localGatewayKey,Supplier<Boolean> meteredEnabled,
                         Supplier<String> routingProvider) {
        this.client=Objects.requireNonNull(client);
        this.externalKey=Objects.requireNonNull(externalKey);
        this.localGatewayKey=Objects.requireNonNull(localGatewayKey);
        this.meteredEnabled=Objects.requireNonNull(meteredEnabled);
        this.routingProvider=Objects.requireNonNull(routingProvider);
    }
    /** Consent is checked at transport boundary, not only in GUI. */
    public HttpRequest build(AssistProfile profile, EvidencePrompt.Packet packet,
                             boolean externalDisclosureApproved) {
        Objects.requireNonNull(profile);
        Objects.requireNonNull(packet);
        boolean external = profile.provider == AssistProfile.Provider.OPENROUTER_FREE
            || profile.provider == AssistProfile.Provider.OPENROUTER_MANAGED;
        if (external && !externalDisclosureApproved) {
            throw new SecurityException("External source disclosure requires explicit per-request approval");
        }
        String lockedProvider=null;
        if (profile.provider == AssistProfile.Provider.OPENROUTER_MANAGED) {
            if (!Boolean.TRUE.equals(meteredEnabled.get()))
                throw new SecurityException("Metered OpenRouter disabled");
            lockedProvider=routingProvider.get();
            if (lockedProvider==null || !lockedProvider.matches("[A-Za-z0-9_. -]{2,64}"))
                throw new SecurityException("Metered route requires an explicit provider");
        }
        JsonObject json=new JsonObject();
        json.addProperty("model",profile.model);
        json.addProperty("stream",false);
        if (profile.provider == AssistProfile.Provider.OLLAMA_LOCAL) {
            json.addProperty("prompt",packet.user);
            json.addProperty("system",packet.system);
            JsonObject options = new JsonObject();
            options.addProperty("temperature",profile.temperature);
            options.addProperty("num_predict",1024);
            json.addProperty("think",profile.role == AssistProfile.Role.REASONING_CANDIDATE);
            if (packet.strictJson) json.addProperty("format","json");
            json.add("options", options);
        } else {
            JsonArray messages=new JsonArray();
            JsonObject sys=new JsonObject(); sys.addProperty("role","system"); sys.addProperty("content",packet.system);
            JsonObject usr=new JsonObject(); usr.addProperty("role","user"); usr.addProperty("content",packet.user);
            messages.add(sys);messages.add(usr);json.add("messages",messages);
            json.addProperty("temperature",profile.temperature);
            if (external) {
                json.addProperty("max_tokens",1024);
                JsonObject routing=new JsonObject();
                routing.addProperty("allow_fallbacks",false);
                routing.addProperty("data_collection","deny");
                if (lockedProvider!=null) {
                    JsonArray only=new JsonArray();only.add(lockedProvider);routing.add("only",only);
                }
                json.add("provider",routing);
            }
            if (external && !"none".equals(profile.reasoningEffort)) {
                JsonObject reasoning=new JsonObject();
                reasoning.addProperty("effort",profile.reasoningEffort);
                json.add("reasoning",reasoning);
            }
        }
        HttpRequest.Builder request=HttpRequest.newBuilder(profile.endpoint)
            .timeout(Duration.ofSeconds(90))
            .header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(json)));
        if (profile.provider == AssistProfile.Provider.OPENAI_LOCAL) {
            String localKey=localGatewayKey.get();
            if (localKey != null && !localKey.isBlank()) {
                request.header("Authorization","Bearer "+localKey);
            }
        }
        if (external) {
            String key=externalKey.get();
            if (key == null || key.isBlank()) {
                throw new SecurityException("OPENROUTER_API_KEY unavailable: no request sent");
            }
            request.header("Authorization","Bearer "+key);
            request.header("X-Title","AAR JADX Actor Assist");
        }
        return request.build();
    }
    public CompletableFuture<Reply> generate(AssistProfile profile, EvidencePrompt.Packet packet,
                                              boolean externalDisclosureApproved) {
        final HttpRequest req;
        try {
            req=build(profile,packet,externalDisclosureApproved);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
        return client.sendAsync(req,HttpResponse.BodyHandlers.ofString())
            .thenApply(response -> {
                // Never echo remote response bodies or headers (possible secret or source leak).
                int status=response.statusCode();
                if (status != 200) {
                    if (status == 429) throw new IllegalStateException("INCOMPLETE_RATE_LIMITED");
                    if (status == 401 || status == 403) throw new IllegalStateException("INCOMPLETE_AUTH");
                    throw new IllegalStateException("INCOMPLETE_HTTP_"+status);
                }
                try {
                    JsonObject body=JsonParser.parseString(response.body()).getAsJsonObject();
                    String value;
                    if (profile.provider == AssistProfile.Provider.OLLAMA_LOCAL) {
                        if (!body.has("done") || !body.get("done").getAsBoolean())
                            throw new IllegalStateException("INCOMPLETE_OLLAMA_NOT_DONE");
                        if (body.has("done_reason") && !body.get("done_reason").isJsonNull()
                            && !"stop".equals(body.get("done_reason").getAsString()))
                            throw new IllegalStateException("INCOMPLETE_OLLAMA_STOP_REASON");
                        value=body.get("response").getAsString();
                    } else {
                        JsonArray choices=body.getAsJsonArray("choices");
                        JsonObject choice=choices.get(0).getAsJsonObject();
                        if (choice.has("finish_reason") && !"stop".equals(choice.get("finish_reason").getAsString())) {
                            throw new IllegalStateException("INCOMPLETE_FINISH_REASON");
                        }
                        value=choice.getAsJsonObject("message").get("content").getAsString();
                    }
                    if (value.isBlank() || value.length()>50000)
                        throw new IllegalStateException("INCOMPLETE_EMPTY_OR_OVERSIZED_RESPONSE");
                    String observed = body.has("model") && !body.get("model").isJsonNull()
                        ? body.get("model").getAsString() : "UNKNOWN_MODEL_ID";
                    if (observed.length() > 180) observed="UNTRUSTED_MODEL_ID_TOO_LONG";
                    return new Reply(value,profile.model,observed,packet.sha256);
                } catch (IllegalStateException e) {
                    throw e;
                } catch (RuntimeException e) {
                    throw new IllegalStateException("INCOMPLETE_INVALID_PROVIDER_RESPONSE");
                }
            });
    }
}
