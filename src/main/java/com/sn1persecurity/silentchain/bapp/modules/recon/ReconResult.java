package com.sn1persecurity.silentchain.bapp.modules.recon;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Aggregated result of a full recon pipeline run.
 * Each field is populated by the corresponding tool (if installed).
 */
public class ReconResult {

    private final String target;
    private final List<String> subdomains = new ArrayList<>();
    private final List<String> aliveDomains = new ArrayList<>();
    private final List<String> httpServices = new ArrayList<>();   // JSON lines from httpx
    private final List<String> openPorts = new ArrayList<>();      // JSON lines from naabu
    private final List<String> wafInfo = new ArrayList<>();
    private final List<String> techFingerprints = new ArrayList<>();
    private final List<String> crawledUrls = new ArrayList<>();
    private final List<String> toolLog = new ArrayList<>();        // execution summary per tool
    private final Map<String, Long> toolDurations = new LinkedHashMap<>();

    public ReconResult(String target) {
        this.target = target;
    }

    // ---- Adders (called by ReconModule as tools finish) --------------------

    public void addSubdomains(List<String> subs) {
        for (String s : subs) {
            String trimmed = s.trim().toLowerCase();
            if (!trimmed.isEmpty() && !subdomains.contains(trimmed)) {
                subdomains.add(trimmed);
            }
        }
    }

    public void addAliveDomains(List<String> alive)     { mergeUnique(aliveDomains, alive); }
    public void addHttpServices(List<String> services)  { httpServices.addAll(services); }
    public void addOpenPorts(List<String> ports)         { openPorts.addAll(ports); }
    public void addWafInfo(List<String> waf)             { wafInfo.addAll(waf); }
    public void addTechFingerprints(List<String> tech)   { techFingerprints.addAll(tech); }
    public void addCrawledUrls(List<String> urls)        { mergeUnique(crawledUrls, urls); }

    public void logTool(String toolName, String status, long durationMs) {
        toolLog.add(toolName + ": " + status + " (" + durationMs + "ms)");
        toolDurations.put(toolName, durationMs);
    }

    // ---- Getters -----------------------------------------------------------

    public String target()               { return target; }
    public List<String> subdomains()     { return subdomains; }
    public List<String> aliveDomains()   { return aliveDomains; }
    public List<String> httpServices()   { return httpServices; }
    public List<String> openPorts()      { return openPorts; }
    public List<String> wafInfo()        { return wafInfo; }
    public List<String> techFingerprints() { return techFingerprints; }
    public List<String> crawledUrls()    { return crawledUrls; }
    public List<String> toolLog()        { return toolLog; }
    public Map<String, Long> toolDurations() { return toolDurations; }

    /** Total unique subdomains found. */
    public int subdomainCount() { return subdomains.size(); }

    /** Total unique alive domains. */
    public int aliveCount() { return aliveDomains.size(); }

    /**
     * Produce a compact text summary for logging / AI analysis.
     */
    public String toSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== RECON RESULT: ").append(target).append(" ===\n\n");

        sb.append("Subdomains found: ").append(subdomains.size()).append("\n");
        for (String s : subdomains) sb.append("  ").append(s).append("\n");

        sb.append("\nAlive domains: ").append(aliveDomains.size()).append("\n");
        for (String s : aliveDomains) sb.append("  ").append(s).append("\n");

        if (!httpServices.isEmpty()) {
            sb.append("\nHTTP Services:\n");
            for (String s : httpServices) sb.append("  ").append(s).append("\n");
        }

        if (!openPorts.isEmpty()) {
            sb.append("\nOpen Ports:\n");
            for (String s : openPorts) sb.append("  ").append(s).append("\n");
        }

        if (!wafInfo.isEmpty()) {
            sb.append("\nWAF Detection:\n");
            for (String s : wafInfo) sb.append("  ").append(s).append("\n");
        }

        if (!techFingerprints.isEmpty()) {
            sb.append("\nTechnology Stack:\n");
            for (String s : techFingerprints) sb.append("  ").append(s).append("\n");
        }

        if (!crawledUrls.isEmpty()) {
            sb.append("\nCrawled URLs: ").append(crawledUrls.size()).append("\n");
            int max = Math.min(crawledUrls.size(), 50);
            for (int i = 0; i < max; i++) sb.append("  ").append(crawledUrls.get(i)).append("\n");
            if (crawledUrls.size() > 50) sb.append("  ... and ").append(crawledUrls.size() - 50).append(" more\n");
        }

        sb.append("\nTool Execution Log:\n");
        for (String log : toolLog) sb.append("  ").append(log).append("\n");

        return sb.toString();
    }

    // ---- Helpers -----------------------------------------------------------

    private static void mergeUnique(List<String> target, List<String> source) {
        for (String s : source) {
            String trimmed = s.trim();
            if (!trimmed.isEmpty() && !target.contains(trimmed)) {
                target.add(trimmed);
            }
        }
    }
}
