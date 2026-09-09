package com.sn1persecurity.silentchain.bapp.modules.recon;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Aggregated result of a full recon pipeline run.
 * Contains both raw tool logs and structured SubdomainEntry objects
 * mapping subdomain -> IP(s) -> Open Ports -> HTTP title & server.
 */
public class ReconResult {

    private final String target;
    private final List<String> subdomains = new ArrayList<>();
    private final List<String> aliveDomains = new ArrayList<>();
    private final List<String> httpServices = new ArrayList<>();
    private final List<String> openPorts = new ArrayList<>();
    private final List<String> wafInfo = new ArrayList<>();
    private final List<String> techFingerprints = new ArrayList<>();
    private final List<String> crawledUrls = new ArrayList<>();
    private final List<String> toolLog = new ArrayList<>();
    private final Map<String, Long> toolDurations = new LinkedHashMap<>();

    // Structured Subdomain Entries mapping (subdomain -> SubdomainEntry)
    private final Map<String, SubdomainEntry> entriesMap = new ConcurrentHashMap<>();

    public ReconResult(String target) {
        this.target = target;
    }

    public synchronized SubdomainEntry getOrCreateEntry(String subdomain) {
        String clean = subdomain.trim().toLowerCase();
        return entriesMap.computeIfAbsent(clean, k -> {
            SubdomainEntry e = new SubdomainEntry(k);
            if (!subdomains.contains(k)) {
                subdomains.add(k);
            }
            return e;
        });
    }

    public List<SubdomainEntry> getEntries() {
        return new ArrayList<>(entriesMap.values());
    }

    // ---- Adders (called by ReconModule as tools finish) --------------------

    public synchronized void addSubdomains(List<String> subs) {
        for (String s : subs) {
            String trimmed = s.trim().toLowerCase();
            if (!trimmed.isEmpty()) {
                getOrCreateEntry(trimmed);
            }
        }
    }

    public synchronized void addAliveDomains(List<String> alive) {
        mergeUnique(aliveDomains, alive);
        for (String a : alive) {
            getOrCreateEntry(a).setAlive(true);
        }
    }

    public synchronized void addHttpServices(List<String> services) {
        httpServices.addAll(services);
    }

    public synchronized void addOpenPorts(List<String> ports) {
        openPorts.addAll(ports);
    }

    public synchronized void addWafInfo(List<String> waf) {
        wafInfo.addAll(waf);
    }

    public synchronized void addTechFingerprints(List<String> tech) {
        techFingerprints.addAll(tech);
    }

    public synchronized void addCrawledUrls(List<String> urls) {
        mergeUnique(crawledUrls, urls);
    }

    public synchronized void logTool(String toolName, String status, long durationMs) {
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

    public int subdomainCount() { return subdomains.size(); }
    public int aliveCount() {
        int c = 0;
        for (SubdomainEntry e : entriesMap.values()) {
            if (e.isAlive()) c++;
        }
        return Math.max(c, aliveDomains.size());
    }

    /**
     * Produce a compact text summary for logging / AI analysis.
     */
    public String toSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== RECON RESULT: ").append(target).append(" ===\n\n");

        sb.append("Subdomains (").append(subdomains.size()).append("):\n");
        for (SubdomainEntry e : entriesMap.values()) {
            sb.append("  • ").append(e.subdomain())
              .append(" -> IP: ").append(e.getIpsString())
              .append(" | Ports: ").append(e.getPortsString())
              .append(" | Title: ").append(e.pageTitle())
              .append(" | Server: ").append(e.serverHeader())
              .append("\n");
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
            int max = Math.min(crawledUrls.size(), 30);
            for (int i = 0; i < max; i++) sb.append("  ").append(crawledUrls.get(i)).append("\n");
            if (crawledUrls.size() > 30) sb.append("  ... and ").append(crawledUrls.size() - 30).append(" more\n");
        }

        sb.append("\nTool Execution Log:\n");
        for (String log : toolLog) sb.append("  ").append(log).append("\n");

        return sb.toString();
    }

    private static void mergeUnique(List<String> target, List<String> source) {
        for (String s : source) {
            String trimmed = s.trim();
            if (!trimmed.isEmpty() && !target.contains(trimmed)) {
                target.add(trimmed);
            }
        }
    }
}
