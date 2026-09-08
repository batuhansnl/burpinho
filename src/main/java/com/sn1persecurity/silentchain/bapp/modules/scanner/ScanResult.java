package com.sn1persecurity.silentchain.bapp.modules.scanner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Aggregated result of a scanner module run.
 */
public class ScanResult {

    private final String target;
    private final List<String> nucleiFindings = new ArrayList<>();    // JSON lines
    private final List<String> dalfoxFindings = new ArrayList<>();    // XSS findings
    private final List<String> sqlmapFindings = new ArrayList<>();    // SQLi findings
    private final List<String> niktoFindings = new ArrayList<>();     // web server findings
    private final List<String> ffufResults = new ArrayList<>();       // fuzzing results
    private final List<String> toolLog = new ArrayList<>();
    private final Map<String, Long> toolDurations = new LinkedHashMap<>();

    public ScanResult(String target) {
        this.target = target;
    }

    public void addNucleiFindings(List<String> f)  { nucleiFindings.addAll(f); }
    public void addDalfoxFindings(List<String> f)  { dalfoxFindings.addAll(f); }
    public void addSqlmapFindings(List<String> f)  { sqlmapFindings.addAll(f); }
    public void addNiktoFindings(List<String> f)   { niktoFindings.addAll(f); }
    public void addFfufResults(List<String> f)     { ffufResults.addAll(f); }

    public void logTool(String toolName, String status, long durationMs) {
        toolLog.add(toolName + ": " + status + " (" + durationMs + "ms)");
        toolDurations.put(toolName, durationMs);
    }

    public String target()                  { return target; }
    public List<String> nucleiFindings()    { return nucleiFindings; }
    public List<String> dalfoxFindings()    { return dalfoxFindings; }
    public List<String> sqlmapFindings()    { return sqlmapFindings; }
    public List<String> niktoFindings()     { return niktoFindings; }
    public List<String> ffufResults()       { return ffufResults; }
    public List<String> toolLog()           { return toolLog; }

    public int totalFindings() {
        return nucleiFindings.size() + dalfoxFindings.size() +
               sqlmapFindings.size() + niktoFindings.size();
    }

    public String toSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== SCAN RESULT: ").append(target).append(" ===\n\n");

        if (!nucleiFindings.isEmpty()) {
            sb.append("Nuclei Findings (").append(nucleiFindings.size()).append("):\n");
            for (String f : nucleiFindings) sb.append("  ").append(f).append("\n");
        }
        if (!dalfoxFindings.isEmpty()) {
            sb.append("\nDalfox XSS Findings (").append(dalfoxFindings.size()).append("):\n");
            for (String f : dalfoxFindings) sb.append("  ").append(f).append("\n");
        }
        if (!sqlmapFindings.isEmpty()) {
            sb.append("\nSQLMap Findings (").append(sqlmapFindings.size()).append("):\n");
            for (String f : sqlmapFindings) sb.append("  ").append(f).append("\n");
        }
        if (!niktoFindings.isEmpty()) {
            sb.append("\nNikto Findings (").append(niktoFindings.size()).append("):\n");
            for (String f : niktoFindings) sb.append("  ").append(f).append("\n");
        }
        if (!ffufResults.isEmpty()) {
            sb.append("\nFfuf Results (").append(ffufResults.size()).append("):\n");
            int max = Math.min(ffufResults.size(), 30);
            for (int i = 0; i < max; i++) sb.append("  ").append(ffufResults.get(i)).append("\n");
        }

        sb.append("\nTool Execution Log:\n");
        for (String log : toolLog) sb.append("  ").append(log).append("\n");

        return sb.toString();
    }
}
