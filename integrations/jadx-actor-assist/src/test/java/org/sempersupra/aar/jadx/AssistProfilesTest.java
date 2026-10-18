package org.sempersupra.aar.jadx;

import org.junit.jupiter.api.Test;
import java.net.URI;
import static org.junit.jupiter.api.Assertions.*;

class AssistProfilesTest {
    @Test void blocksNonfreeModelsAndSubstitutedRouter() {
        assertThrows(IllegalArgumentException.class, () -> new AssistProfile(
            AssistProfile.Provider.OPENROUTER_FREE, AssistProfile.Role.REASONING_CANDIDATE,
            "paid/model",URI.create("https://openrouter.ai/api/v1/chat/completions"),0.2,"medium"));
        assertThrows(IllegalArgumentException.class, () -> new AssistProfile(
            AssistProfile.Provider.OPENROUTER_FREE, AssistProfile.Role.REASONING_CANDIDATE,
            "good/model:free",URI.create("https://attacker.example/api/v1/chat/completions"),0.2,"medium"));
        assertThrows(IllegalArgumentException.class, () -> new AssistProfile(
            AssistProfile.Provider.OPENROUTER_FREE, AssistProfile.Role.REASONING_CANDIDATE,
            "good/model:free",URI.create("http://openrouter.ai/api/v1/chat/completions"),0.2,"medium"));
    }
    @Test void admitsNamedFreeRouterButNotArbitraryModel() {
        assertDoesNotThrow(() -> new AssistProfile(
            AssistProfile.Provider.OPENROUTER_FREE, AssistProfile.Role.REASONING_CANDIDATE,
            "openrouter/free",URI.create("https://openrouter.ai/api/v1/chat/completions"),0.2,"medium"));
    }
    @Test void permitsLocalInterfacesButNotPublicHttp() {
        assertDoesNotThrow(() -> new AssistProfile(AssistProfile.Provider.OPENAI_LOCAL,
            AssistProfile.Role.DETERMINISTIC_CANDIDATE,"qwen",URI.create("http://127.0.0.1:8080/v1/chat/completions"),0,"none"));
        assertDoesNotThrow(() -> new AssistProfile(AssistProfile.Provider.OLLAMA_LOCAL,
            AssistProfile.Role.REASONING_CANDIDATE,"qwen",URI.create("http://192.168.178.49:30068/api/generate"),0.2,"none"));
        assertThrows(IllegalArgumentException.class, () -> new AssistProfile(AssistProfile.Provider.OPENAI_LOCAL,
            AssistProfile.Role.REASONING_CANDIDATE,"qwen",URI.create("http://example.com/v1/chat/completions"),0.2,"none"));
    }
    @Test void cannotInjectModelHeaderOrOversize() {
        assertThrows(IllegalArgumentException.class, () -> new AssistProfile(
            AssistProfile.Provider.OPENAI_LOCAL,AssistProfile.Role.REASONING_CANDIDATE,
            "model\nX-Test: y",URI.create("http://localhost:8080/v1/chat/completions"),0.1,"none"));
    }
}
