package com.sn1persecurity.silentchain.bapp.ai.providers;

/**
 * Provider identifiers focused on Local LLMs (OpenAI-compatible and Ollama).
 */
public enum ProviderId {
    OPENAI        ("OpenAI Compatible (Local/Custom)",  "http://localhost:8000/v1"),
    OLLAMA        ("Ollama (Local)",                   "http://localhost:11434");

    private final String displayName;
    private final String defaultUrl;

    ProviderId(String displayName, String defaultUrl) {
        this.displayName = displayName;
        this.defaultUrl = defaultUrl;
    }

    public String displayName() { return displayName; }
    public String defaultUrl() { return defaultUrl; }

    public static ProviderId fromDisplayName(String name) {
        if (name == null) return OPENAI;
        for (ProviderId p : values()) {
            if (p.displayName.equalsIgnoreCase(name.trim()) || p.name().equalsIgnoreCase(name.trim())) {
                return p;
            }
        }
        return OPENAI;
    }
}
