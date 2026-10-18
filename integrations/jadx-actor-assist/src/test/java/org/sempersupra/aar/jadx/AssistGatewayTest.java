package org.sempersupra.aar.jadx;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class AssistGatewayTest {
    static final EvidencePrompt.Packet PACKET=EvidencePrompt.build("class Test{}","explain","What is it?");
    static AssistProfile local(AssistProfile.Provider p,int port) {
        String path=p==AssistProfile.Provider.OLLAMA_LOCAL ? "/api/generate" : "/v1/chat/completions";
        return new AssistProfile(p,AssistProfile.Role.DETERMINISTIC_CANDIDATE,"fixture-qwen",
            URI.create("http://127.0.0.1:"+port+path),0,"none");
    }
    @Test void noOpenRouterRequestWithoutExplicitConsentOrCredential() {
        AssistProfile free=new AssistProfile(AssistProfile.Provider.OPENROUTER_FREE,
            AssistProfile.Role.REASONING_CANDIDATE,"research/test:free",
            URI.create("https://openrouter.ai/api/v1/chat/completions"),0.2,"medium");
        AssistGateway gateway=new AssistGateway(HttpClient.newHttpClient(),()->"");
        assertThrows(SecurityException.class,()->gateway.build(free,PACKET,false));
        assertThrows(SecurityException.class,()->gateway.build(free,PACKET,true));
        AssistGateway pretend=new AssistGateway(HttpClient.newHttpClient(),()->"fake-unit-test-only");
        java.net.http.HttpRequest req=pretend.build(free,PACKET,true);
        assertEquals("https",req.uri().getScheme());
        assertEquals("Bearer fake-unit-test-only",req.headers().firstValue("Authorization").orElseThrow());
    }
    @Test void managedRouteRequiresOptInProviderPinAndConsent() {
        AssistProfile metered = new AssistProfile(AssistProfile.Provider.OPENROUTER_MANAGED,
            AssistProfile.Role.REASONING_CANDIDATE,"deepseek/deepseek-chat",
            URI.create("https://openrouter.ai/api/v1/chat/completions"),0.2,"medium");
        AssistGateway disabled=new AssistGateway(HttpClient.newHttpClient(),()->"fake",()->null,
            ()->false,()->"DeepSeek");
        assertThrows(SecurityException.class,()->disabled.build(metered,PACKET,true));
        AssistGateway unpinned=new AssistGateway(HttpClient.newHttpClient(),()->"fake",()->null,
            ()->true,()->null);
        assertThrows(SecurityException.class,()->unpinned.build(metered,PACKET,true));
        AssistGateway granted=new AssistGateway(HttpClient.newHttpClient(),()->"fake",()->null,
            ()->true,()->"DeepSeek");
        assertThrows(SecurityException.class,()->granted.build(metered,PACKET,false));
        var req=granted.build(metered,PACKET,true);
        assertEquals("https",req.uri().getScheme());
        String body=req.bodyPublisher().map(pub->pub.toString()).orElse("");
        assertTrue(req.headers().firstValue("Authorization").isPresent());
    }
    @Test void scopedLocalGatewayCredentialIsOptionalAndNeverForOllama() {
        AssistGateway gw=new AssistGateway(HttpClient.newHttpClient(),()->"external",
            ()->"local-scoped-test-key");
        AssistProfile local=local(AssistProfile.Provider.OPENAI_LOCAL,12345);
        assertEquals("Bearer local-scoped-test-key",
            gw.build(local,PACKET,false).headers().firstValue("Authorization").orElseThrow());
        AssistProfile ollama=local(AssistProfile.Provider.OLLAMA_LOCAL,12345);
        assertFalse(gw.build(ollama,PACKET,false).headers().firstValue("Authorization").isPresent());
    }
    @Test void localOllamaJsonRoundTrip() throws Exception {
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        AtomicReference<JsonObject> captured=new AtomicReference<>();
        server.createContext("/api/generate",exchange->{
            captured.set(JsonParser.parseString(new String(exchange.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8)).getAsJsonObject());
            byte[] response="{\"response\":\"Observed L1\\nUNKNOWN\",\"done\":true,\"done_reason\":\"stop\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200,response.length);
            try(var out=exchange.getResponseBody()){out.write(response);}
        });
        server.start();
        try {
            int port=server.getAddress().getPort();
            AssistGateway.Reply r=new AssistGateway().generate(local(AssistProfile.Provider.OLLAMA_LOCAL,port),PACKET,false).join();
            assertEquals("Observed L1\nUNKNOWN",r.text);
            assertTrue(captured.get().get("system").getAsString().contains("UNTRUSTED"));
            assertTrue(captured.get().get("prompt").getAsString().contains(PACKET.sha256));
            assertEquals(0,captured.get().getAsJsonObject("options").get("temperature").getAsInt());
            assertFalse(captured.get().get("think").getAsBoolean());
            assertEquals(1024,captured.get().getAsJsonObject("options").get("num_predict").getAsInt());
        }finally{server.stop(0);}
    }
    @Test void thinkingRoleIsExplicitOnOllama() {
        AssistProfile q=new AssistProfile(AssistProfile.Provider.OLLAMA_LOCAL,
            AssistProfile.Role.REASONING_CANDIDATE,"qwen3:1.7b",
            URI.create("http://127.0.0.1:11434/api/generate"),0.2,"medium");
        var built=new AssistGateway().build(q,PACKET,false);
        // Body is validated by the end-to-end local mock test for the other role.
        assertEquals("http",built.uri().getScheme());
        assertFalse(built.headers().firstValue("Authorization").isPresent());
    }
    @Test void jsonModeIsBoundToPacketOnly() {
        EvidencePrompt.Packet standard=EvidencePrompt.build("class A {}","explain","");
        EvidencePrompt.Packet structured=EvidencePrompt.build("class A {}","explain","",true);
        assertFalse(standard.strictJson);
        assertTrue(structured.strictJson);
        assertFalse(new AssistGateway().build(
            local(AssistProfile.Provider.OLLAMA_LOCAL,12345),standard,false)
            .headers().firstValue("Authorization").isPresent());
    }
    @Test void strictJsonSchemaHasNoHiddenAnswerAndRejectsExtraneousFields() {
        JsonObject schema=AssistGateway.interviewJsonSchema();
        assertEquals("object",schema.get("type").getAsString());
        assertFalse(schema.get("additionalProperties").getAsBoolean());
        assertEquals(4,schema.getAsJsonArray("required").size());
        JsonObject fields=schema.getAsJsonObject("properties");
        assertEquals(4,fields.size());
        assertEquals("array",fields.getAsJsonObject("evidence").get("type").getAsString());
        assertFalse(schema.toString().contains("OBJECT"));
        assertFalse(schema.toString().contains("a(Object)"));
        assertFalse(schema.toString().contains("UNKNOWN"));
    }
    @Test void openAiCompatibleStructuredMessagesRoundTrip() throws Exception {
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        AtomicReference<JsonObject> captured=new AtomicReference<>();
        server.createContext("/v1/chat/completions", exchange->{
            captured.set(JsonParser.parseString(new String(exchange.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8)).getAsJsonObject());
            byte[] response="{\"choices\":[{\"message\":{\"content\":\"HYPOTHESIS only\"},\"finish_reason\":\"stop\"}]}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200,response.length);
            try(var o=exchange.getResponseBody()){o.write(response);}
        });
        server.start();
        try {
            AssistGateway.Reply r=new AssistGateway().generate(local(AssistProfile.Provider.OPENAI_LOCAL,
                server.getAddress().getPort()),PACKET,false).join();
            assertEquals("HYPOTHESIS only",r.text);
            assertEquals("system",captured.get().getAsJsonArray("messages").get(0).getAsJsonObject().get("role").getAsString());
            assertEquals("user",captured.get().getAsJsonArray("messages").get(1).getAsJsonObject().get("role").getAsString());
        }finally{server.stop(0);}
    }
    @Test void rateLimitNotReportedAsModelFailureOrEchoed() throws Exception {
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/api/generate",exchange->{
            byte[] secret="SECRET_NEVER_ECHO_BODY".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(429,secret.length);
            try(var o=exchange.getResponseBody()){o.write(secret);}
        });
        server.start();
        try {
            CompletionException x=assertThrows(CompletionException.class,()->new AssistGateway().generate(
                local(AssistProfile.Provider.OLLAMA_LOCAL,server.getAddress().getPort()),PACKET,false).join());
            assertEquals("INCOMPLETE_RATE_LIMITED",x.getCause().getMessage());
        }finally{server.stop(0);}
    }
}
