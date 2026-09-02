package com.sn1persecurity.silentchain.bapp.ai.providers;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient.HttpReply;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * OpenAI provider (and compatible APIs like vLLM, Ollama, LocalAI, etc.).
 *
 * Endpoints (default URL https://api.openai.com/v1):
 *   POST /chat/completions
 *   GET  /models
 *
 * Auth: Authorization: Bearer <apiKey> (optional for local endpoints)
 */
public class OpenAiProvider implements LlmProvider {

    private final MontoyaApi api;
    private final MontoyaHttpClient http;
    private final Settings settings;

    public OpenAiProvider(MontoyaApi api, MontoyaHttpClient http, Settings settings) {
        this.api = api;
        this.http = http;
        this.settings = settings;
    }

    @Override public ProviderId id() { return ProviderId.OPENAI; }

    @Override public boolean usesApiKey() { return true; }

    @Override
    public boolean isAvailable() {
        return !baseUrl().isBlank();
    }

    private Map<String, String> authHeaders() {
        String key = settings.apiKey();
        if (key != null && !key.isBlank()) {
            return MontoyaHttpClient.bearer(key);
        }
        return Collections.emptyMap();
    }

    @Override
    public List<String> listModels() {
        HttpReply r = http.get(baseUrl() + "/models", authHeaders());
        if (!r.ok()) return List.of();
        try {
            JSONObject obj = new JSONObject(r.body());
            JSONArray arr = obj.optJSONArray("data");
            if (arr == null) return List.of();
            List<String> models = new ArrayList<>();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject m = arr.optJSONObject(i);
                if (m != null) {
                    String id = m.optString("id", "");
                    if (!id.isBlank()) models.add(id);
                }
            }
            return models;
        } catch (JSONException e) {
            return List.of();
        }
    }

    @Override
    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        if (!isAvailable()) {
            api.logging().logToError("OpenAI: missing API URL.");
            return Optional.empty();
        }
        String model = settings.model();
        if (model.isBlank()) model = "gpt-4o-mini";

        JSONObject body = new JSONObject();
        body.put("model", model);
        body.put("max_tokens", settings.maxTokens());
        body.put("temperature", 0.0);

        JSONArray messages = new JSONArray();
        messages.put(new JSONObject().put("role", "system").put("content", systemPrompt));
        messages.put(new JSONObject().put("role", "user").put("content", userPrompt));
        body.put("messages", messages);

        HttpReply r = http.postJson(baseUrl() + "/chat/completions", authHeaders(), body.toString());
        if (!r.ok()) {
            api.logging().logToError("OpenAI HTTP " + r.status() + ": " + truncate(r.body()));
            return Optional.empty();
        }
        try {
            JSONObject obj = new JSONObject(r.body());
            JSONArray choices = obj.optJSONArray("choices");
            if (choices == null || choices.length() == 0) return Optional.empty();
            JSONObject msg = choices.getJSONObject(0).optJSONObject("message");
            if (msg == null) return Optional.empty();
            String content = msg.optString("content", "");
            return content.isBlank() ? Optional.empty() : Optional.of(content);
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    @Override
    public TestResult testConnection() {
        if (baseUrl().isBlank()) return TestResult.fail("OpenAI URL is empty.");
        
        // 1. First try GET /models
        HttpReply r = http.get(baseUrl() + "/models", authHeaders());
        if (r.ok()) {
            List<String> models = listModels();
            String extra = models.isEmpty() ? "" : " (" + models.size() + " models loaded)";
            return TestResult.ok("Connected to OpenAI endpoint successfully!" + extra);
        }
        
        if (r.status() == 401) {
            return TestResult.fail("OpenAI rejected the API key (HTTP 401).");
        }

        // 2. Fallback: Some local servers don't implement /models. Try a minimal chat/completions test.
        String testModel = settings.model().isBlank() ? "default" : settings.model();
        JSONObject testBody = new JSONObject();
        testBody.put("model", testModel);
        testBody.put("max_tokens", 1);
        JSONArray msgs = new JSONArray();
        msgs.put(new JSONObject().put("role", "user").put("content", "ping"));
        testBody.put("messages", msgs);

        HttpReply chatReply = http.postJson(baseUrl() + "/chat/completions", authHeaders(), testBody.toString());
        if (chatReply.ok() || (chatReply.status() >= 200 && chatReply.status() < 500 && chatReply.status() != 404)) {
            return TestResult.ok("OpenAI endpoint reachable via /chat/completions.");
        }

        if (r.status() == 0 && chatReply.status() == 0) {
            return TestResult.fail("OpenAI unreachable (Check IP/Port, Burp Upstream Proxy / SOCKS settings, or use http:// instead of https://).");
        }

        return TestResult.fail("OpenAI returned HTTP " + (r.status() != 0 ? r.status() : chatReply.status()) + ".");
    }

    private String baseUrl() {
        String configured = settings.apiUrl();
        String url = configured != null && !configured.isBlank() ? configured : id().defaultUrl();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() > 240 ? s.substring(0, 240) + "..." : s;
    }
}
