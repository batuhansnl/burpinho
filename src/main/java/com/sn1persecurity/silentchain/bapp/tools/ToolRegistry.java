package com.sn1persecurity.silentchain.bapp.tools;

import burp.api.montoya.MontoyaApi;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of all supported external security tools.
 * Detects which tools are installed on the system via "which" / "where" commands,
 * and provides metadata (install instructions, category, etc.) for each tool.
 */
public class ToolRegistry {

    private final MontoyaApi api;
    private final Map<String, String> pathCache = new ConcurrentHashMap<>();
    private volatile boolean scanned = false;

    /** All tools burpinho knows about, keyed by name. */
    private static final Map<String, ToolInfo> ALL_TOOLS = new LinkedHashMap<>();

    static {
        // ---- RECON ----
        reg("subfinder",    "Fast passive subdomain enumeration",
                ToolInfo.Category.RECON, "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", true);
        reg("amass",        "In-depth subdomain enumeration",
                ToolInfo.Category.RECON, "go install github.com/owasp-amass/amass/v4/...@master", false);
        reg("assetfinder",  "Find related domains and subdomains",
                ToolInfo.Category.RECON, "go install github.com/tomnomnom/assetfinder@latest", false);
        reg("dnsx",         "Fast DNS resolver / brute-forcer",
                ToolInfo.Category.RECON, "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", false);
        reg("httpx",        "HTTP probe with tech-detect, title, status",
                ToolInfo.Category.RECON, "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", true);
        reg("naabu",        "Fast port scanner",
                ToolInfo.Category.RECON, "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", false);
        reg("katana",       "Web crawler / spider",
                ToolInfo.Category.RECON, "go install github.com/projectdiscovery/katana/cmd/katana@latest", false);
        reg("wafw00f",      "WAF detection",
                ToolInfo.Category.RECON, "pip3 install wafw00f", false);
        reg("whatweb",      "Web technology fingerprinting",
                ToolInfo.Category.RECON, "brew install whatweb  OR  apt install whatweb", false);
        reg("gowitness",    "Website screenshot",
                ToolInfo.Category.RECON, "go install github.com/sensepost/gowitness@latest", false);

        // ---- SCANNER ----
        reg("nuclei",       "Template-based vulnerability scanner",
                ToolInfo.Category.SCANNER, "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", true);
        reg("dalfox",       "XSS scanner with DOM analysis",
                ToolInfo.Category.SCANNER, "go install github.com/hahwul/dalfox/v2@latest", false);
        reg("sqlmap",       "Automatic SQL injection tool",
                ToolInfo.Category.SCANNER, "pip3 install sqlmap  OR  apt install sqlmap", false);
        reg("nikto",        "Web server scanner",
                ToolInfo.Category.SCANNER, "brew install nikto  OR  apt install nikto", false);
        reg("ffuf",         "Fast web fuzzer",
                ToolInfo.Category.SCANNER, "go install github.com/ffuf/ffuf/v2@latest", false);

        // ---- EXPLOIT ----
        reg("searchsploit", "Exploit-DB search tool",
                ToolInfo.Category.EXPLOIT, "apt install exploitdb  OR  brew install exploitdb", false);

        // ---- UTILITY ----
        reg("jq",           "JSON processor",
                ToolInfo.Category.UTILITY, "brew install jq  OR  apt install jq", false);
        reg("anew",         "Append new unique lines to file",
                ToolInfo.Category.UTILITY, "go install github.com/tomnomnom/anew@latest", false);
    }

    public ToolRegistry(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Check if a tool is installed and available on PATH.
     * Results are cached after the first check.
     */
    public boolean isInstalled(String toolName) {
        return getPath(toolName) != null;
    }

    /**
     * Get the absolute path to a tool, or null if not found.
     */
    public String getPath(String toolName) {
        return pathCache.computeIfAbsent(toolName, this::findTool);
    }

    /**
     * Scan for all tools and cache results. Call this at extension load time.
     */
    public void scanAll() {
        if (scanned) return;
        api.logging().logToOutput("ToolRegistry: scanning for installed tools...");
        int installed = 0;
        for (String name : ALL_TOOLS.keySet()) {
            if (isInstalled(name)) {
                installed++;
            }
        }
        scanned = true;
        api.logging().logToOutput("ToolRegistry: " + installed + "/" + ALL_TOOLS.size() + " tools found.");
    }

    /** Invalidate cache, re-scan on next access. */
    public void refresh() {
        pathCache.clear();
        scanned = false;
    }

    /** All known tools (installed or not). */
    public List<ToolInfo> getAllTools() {
        return new ArrayList<>(ALL_TOOLS.values());
    }

    /** Only tools that are installed. */
    public List<ToolInfo> getInstalledTools() {
        List<ToolInfo> out = new ArrayList<>();
        for (ToolInfo info : ALL_TOOLS.values()) {
            if (isInstalled(info.name())) {
                out.add(info);
            }
        }
        return out;
    }

    /** Only tools that are NOT installed. */
    public List<ToolInfo> getMissingTools() {
        List<ToolInfo> out = new ArrayList<>();
        for (ToolInfo info : ALL_TOOLS.values()) {
            if (!isInstalled(info.name())) {
                out.add(info);
            }
        }
        return out;
    }

    /** Tools in a specific category. */
    public List<ToolInfo> getToolsByCategory(ToolInfo.Category category) {
        List<ToolInfo> out = new ArrayList<>();
        for (ToolInfo info : ALL_TOOLS.values()) {
            if (info.category() == category) {
                out.add(info);
            }
        }
        return out;
    }

    /** Get ToolInfo by name. */
    public ToolInfo getInfo(String toolName) {
        return ALL_TOOLS.get(toolName);
    }

    /** Human-readable status for UI display. */
    public String statusSummary() {
        int installed = 0;
        int total = ALL_TOOLS.size();
        for (String name : ALL_TOOLS.keySet()) {
            if (isInstalled(name)) installed++;
        }
        return installed + "/" + total + " tools installed";
    }

    // ---- Private helpers ----------------------------------------------------

    private String findTool(String name) {
        // 1. Check common paths directly (faster than which)
        String[] commonPaths = {
            "/usr/local/bin/" + name,
            "/usr/bin/" + name,
            "/opt/homebrew/bin/" + name,
            System.getProperty("user.home") + "/go/bin/" + name,
            System.getProperty("user.home") + "/.local/bin/" + name,
            "/snap/bin/" + name
        };

        for (String path : commonPaths) {
            File f = new File(path);
            if (f.exists() && f.canExecute()) {
                api.logging().logToOutput("ToolRegistry: found " + name + " at " + path);
                return path;
            }
        }

        // 2. Fall back to "which" command
        try {
            ProcessBuilder pb = new ProcessBuilder("which", name);
            pb.environment().putAll(System.getenv());
            String path = pb.environment().getOrDefault("PATH", "");
            pb.environment().put("PATH",
                    path + ":/usr/local/bin:/usr/bin:/opt/homebrew/bin"
                    + ":" + System.getProperty("user.home") + "/go/bin"
                    + ":" + System.getProperty("user.home") + "/.local/bin");

            Process p = pb.start();
            String result = new String(p.getInputStream().readAllBytes()).trim();
            boolean ok = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) && p.exitValue() == 0;
            if (ok && !result.isEmpty()) {
                api.logging().logToOutput("ToolRegistry: found " + name + " via which: " + result);
                return result;
            }
        } catch (Throwable t) {
            // Not found
        }

        return null; // sentinel stored in ConcurrentHashMap won't work, handle in isInstalled
    }

    private static void reg(String name, String desc, ToolInfo.Category cat, String installCmd, boolean required) {
        ALL_TOOLS.put(name, new ToolInfo(name, desc, cat, installCmd, required));
    }
}
