package com.sn1persecurity.silentchain.bapp.tools;

import burp.api.montoya.MontoyaApi;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of security tools and built-in engines.
 * burpinho is 100% self-contained and pure Java — every tool has a built-in engine
 * requiring zero external installation (ideal for locked-down enterprise Windows/Mac/Linux).
 * If external CLI binaries exist on PATH, they can optionally be used as accelerators.
 */
public class ToolRegistry {

    private final MontoyaApi api;
    private final Map<String, String> pathCache = new ConcurrentHashMap<>();
    private volatile boolean scanned = false;

    /** All tools and engines burpinho supports, keyed by name. */
    private static final Map<String, ToolInfo> ALL_TOOLS = new LinkedHashMap<>();

    static {
        // ---- RECON (100% Built-in Pure Java) ----
        reg("subfinder",    "Passive subdomain enum (Built-in + CLI)",
                ToolInfo.Category.RECON, "100% Built-in (HackerTarget, crt.sh & DNS Wordlist)", false);
        reg("dnsx",         "DNS resolution & alive check (Built-in + CLI)",
                ToolInfo.Category.RECON, "100% Built-in (Multi-threaded Java DNS Resolver)", false);
        reg("httpx",        "HTTP probe, title, status, server (Built-in + CLI)",
                ToolInfo.Category.RECON, "100% Built-in (Parallel Java HTTP Prober)", false);
        reg("naabu",        "Fast port scanner for top ports (Built-in + CLI)",
                ToolInfo.Category.RECON, "100% Built-in (Multi-threaded Socket Scanner)", false);
        reg("wafw00f",      "WAF signature detection (Built-in + CLI)",
                ToolInfo.Category.RECON, "100% Built-in (20+ WAF Header/Cookie Signatures)", false);
        reg("whatweb",      "Tech stack & CMS fingerprinting (Built-in + CLI)",
                ToolInfo.Category.RECON, "100% Built-in (40+ Framework & CMS Signatures)", false);
        reg("katana",       "Web crawler & endpoint spider (Built-in + CLI)",
                ToolInfo.Category.RECON, "100% Built-in (HTML/JS Recursive Link Extractor)", false);

        // ---- SCANNER (100% Built-in Pure Java) ----
        reg("nuclei",       "Vulnerability & CVE templates (Built-in + CLI)",
                ToolInfo.Category.SCANNER, "100% Built-in (50+ Sensitive File & API Exposure Checks)", false);
        reg("dalfox",       "XSS detection & reflection analysis (Built-in + CLI)",
                ToolInfo.Category.SCANNER, "100% Built-in (Active XSS Parameter Reflection Engine)", false);
        reg("sqlmap",       "SQL injection detection (Built-in + CLI)",
                ToolInfo.Category.SCANNER, "100% Built-in (Error-based & Boolean SQLi Analyzer)", false);
        reg("nikto",        "Web server security & misconfig (Built-in + CLI)",
                ToolInfo.Category.SCANNER, "100% Built-in (Security Headers, CORS & Config Probes)", false);
        reg("ffuf",         "Endpoint fuzzing & discovery (Built-in + CLI)",
                ToolInfo.Category.SCANNER, "100% Built-in (Embedded Wordlist Path Fuzzer)", false);

        // ---- EXPLOIT (100% Built-in Pure Java + Local AI) ----
        reg("searchsploit", "Exploit & PoC knowledgebase (Built-in + AI)",
                ToolInfo.Category.EXPLOIT, "100% Built-in + Local AI Exploit Advisor", false);

        // ---- UTILITY ----
        reg("anew",         "Deduplication engine",
                ToolInfo.Category.UTILITY, "100% Built-in (Java Set/Stream Deduplicator)", false);
    }

    public ToolRegistry(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Check if a tool is available (all tools are always available via built-in engines).
     */
    public boolean isInstalled(String toolName) {
        return true;
    }

    /**
     * Returns whether an external CLI binary is detected on the OS PATH.
     */
    public boolean isCliBinaryDetected(String toolName) {
        String path = getPath(toolName);
        return path != null && !path.isEmpty();
    }

    /**
     * Get the absolute path to an external CLI binary if available, or null.
     */
    public String getPath(String toolName) {
        String cached = pathCache.get(toolName);
        if (cached != null) {
            return cached.isEmpty() ? null : cached;
        }
        String found = findTool(toolName);
        pathCache.put(toolName, found != null ? found : "");
        return found;
    }

    public void scanAll() {
        if (scanned) return;
        api.logging().logToOutput("ToolRegistry: burpinho 100% built-in engines ready.");
        int cliFound = 0;
        for (String name : ALL_TOOLS.keySet()) {
            if (isCliBinaryDetected(name)) {
                cliFound++;
            }
        }
        scanned = true;
        api.logging().logToOutput("ToolRegistry: " + ALL_TOOLS.size() + " built-in engines ready ("
                + cliFound + " external CLI binaries detected as optional accelerators).");
    }

    public void refresh() {
        pathCache.clear();
        scanned = false;
    }

    public List<ToolInfo> getAllTools() {
        return new ArrayList<>(ALL_TOOLS.values());
    }

    public ToolInfo getInfo(String toolName) {
        return ALL_TOOLS.get(toolName);
    }

    public String statusSummary() {
        return ALL_TOOLS.size() + " Built-in Engines Ready (100% Pure Java — Zero Setup)";
    }

    // ---- Private helpers ----------------------------------------------------

    private String findTool(String name) {
        String userHome = System.getProperty("user.home", "");

        String[] commonPaths = {
            "/opt/homebrew/bin/" + name,
            "/opt/homebrew/sbin/" + name,
            "/usr/local/bin/" + name,
            "/usr/bin/" + name,
            "/bin/" + name,
            "/usr/sbin/" + name,
            "/sbin/" + name,
            userHome + "/go/bin/" + name,
            userHome + "/.local/bin/" + name,
            userHome + "/.cargo/bin/" + name,
            "C:\\Program Files\\" + name + "\\" + name + ".exe",
            "C:\\ProgramData\\chocolatey\\bin\\" + name + ".exe",
            "C:\\Tools\\" + name + "\\" + name + ".exe",
            userHome + "\\go\\bin\\" + name + ".exe"
        };

        for (String path : commonPaths) {
            File f = new File(path);
            if (f.exists() && f.canExecute()) {
                api.logging().logToOutput("ToolRegistry: detected CLI binary for " + name + " at " + path);
                return path;
            }
        }

        try {
            String whichCmd = System.getProperty("os.name", "").toLowerCase().contains("win") ? "where" : "which";
            ProcessBuilder pb = new ProcessBuilder(whichCmd, name);
            pb.environment().putAll(System.getenv());
            String envPath = pb.environment().getOrDefault("PATH", "");
            pb.environment().put("PATH",
                    "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:"
                    + userHome + "/go/bin:"
                    + userHome + "/.local/bin:"
                    + userHome + "/.cargo/bin:"
                    + envPath);

            Process p = pb.start();
            String result = new String(p.getInputStream().readAllBytes()).trim();
            boolean ok = p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) && p.exitValue() == 0;
            if (ok && !result.isEmpty() && new File(result).canExecute()) {
                api.logging().logToOutput("ToolRegistry: detected " + name + " via " + whichCmd + ": " + result);
                return result;
            }
        } catch (Throwable ignored) {}

        return null;
    }

    private static void reg(String name, String desc, ToolInfo.Category cat, String installCmd, boolean required) {
        ALL_TOOLS.put(name, new ToolInfo(name, desc, cat, installCmd, required));
    }
}
