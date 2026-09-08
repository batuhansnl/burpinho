package com.sn1persecurity.silentchain.bapp.modules.report;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.ai.AiDispatcher;
import com.sn1persecurity.silentchain.bapp.modules.recon.ReconResult;
import com.sn1persecurity.silentchain.bapp.modules.scanner.ScanResult;
import com.sn1persecurity.silentchain.bapp.state.FindingRow;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * REPORT module — generates comprehensive HTML/Markdown reports
 * from all module outputs (Recon, Scanner, Exploit, Passive AI).
 *
 * AI is used optionally for:
 *   - Executive summary generation
 *   - Risk scoring
 *   - Remediation prioritization
 *   - Compliance mapping (PCI-DSS, ISO 27001)
 */
public class ReportModule {

    private final MontoyaApi api;
    private final AiDispatcher aiDispatcher;
    private final FindingsRegistry findingsRegistry;

    public ReportModule(MontoyaApi api, AiDispatcher aiDispatcher, FindingsRegistry findingsRegistry) {
        this.api = api;
        this.aiDispatcher = aiDispatcher;
        this.findingsRegistry = findingsRegistry;
    }

    /**
     * Generate a full HTML report combining all module results.
     *
     * @param recon   recon results (nullable)
     * @param scan    scan results (nullable)
     * @param outputDir  directory to save the report
     * @param progress   status callback
     * @return path to the generated report file
     */
    public String generateReport(ReconResult recon, ScanResult scan,
                                  String outputDir, Consumer<String> progress) {
        Consumer<String> log = msg -> {
            if (progress != null) progress.accept(msg);
            api.logging().logToOutput("REPORT: " + msg);
        };

        log.accept("Generating report...");

        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String filename = "burpinho_report_" + timestamp + ".html";
        String filepath = outputDir + File.separator + filename;

        StringBuilder html = new StringBuilder();
        html.append(htmlHeader());

        // ---- Title ----
        String target = "";
        if (recon != null) target = recon.target();
        else if (scan != null) target = scan.target();

        html.append("<div class='container'>\n");
        html.append("<h1>burpinho Security Report</h1>\n");
        html.append("<p class='subtitle'>Target: <strong>").append(escHtml(target)).append("</strong></p>\n");
        html.append("<p class='subtitle'>Generated: ").append(LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("</p>\n");

        // ---- Executive Summary (AI) ----
        html.append(generateExecutiveSummary(recon, scan, log));

        // ---- Passive AI Findings ----
        List<FindingRow> passiveFindings = findingsRegistry.snapshot();
        if (!passiveFindings.isEmpty()) {
            html.append("<h2>AI Passive Analysis Findings</h2>\n");
            html.append("<table><thead><tr><th>URL</th><th>Finding</th><th>Severity</th><th>Confidence</th></tr></thead><tbody>\n");
            for (FindingRow f : passiveFindings) {
                html.append("<tr class='severity-").append(f.severity().toLowerCase()).append("'>")
                    .append("<td>").append(escHtml(f.url())).append("</td>")
                    .append("<td>").append(escHtml(f.finding())).append("</td>")
                    .append("<td>").append(escHtml(f.severity())).append("</td>")
                    .append("<td>").append(escHtml(f.confidence())).append("</td>")
                    .append("</tr>\n");
            }
            html.append("</tbody></table>\n");
        }

        // ---- Recon Results ----
        if (recon != null) {
            html.append("<h2>Reconnaissance Results</h2>\n");

            if (!recon.subdomains().isEmpty()) {
                html.append("<h3>Subdomains (").append(recon.subdomainCount()).append(")</h3>\n<ul>\n");
                for (String s : recon.subdomains()) html.append("<li>").append(escHtml(s)).append("</li>\n");
                html.append("</ul>\n");
            }

            if (!recon.httpServices().isEmpty()) {
                html.append("<h3>HTTP Services</h3>\n<pre class='output'>\n");
                for (String s : recon.httpServices()) html.append(escHtml(s)).append("\n");
                html.append("</pre>\n");
            }

            if (!recon.openPorts().isEmpty()) {
                html.append("<h3>Open Ports</h3>\n<pre class='output'>\n");
                for (String s : recon.openPorts()) html.append(escHtml(s)).append("\n");
                html.append("</pre>\n");
            }

            if (!recon.wafInfo().isEmpty()) {
                html.append("<h3>WAF Detection</h3>\n<pre class='output'>\n");
                for (String s : recon.wafInfo()) html.append(escHtml(s)).append("\n");
                html.append("</pre>\n");
            }

            if (!recon.techFingerprints().isEmpty()) {
                html.append("<h3>Technology Stack</h3>\n<pre class='output'>\n");
                for (String s : recon.techFingerprints()) html.append(escHtml(s)).append("\n");
                html.append("</pre>\n");
            }

            html.append("<h3>Recon Tool Log</h3>\n<pre class='output'>\n");
            for (String s : recon.toolLog()) html.append(escHtml(s)).append("\n");
            html.append("</pre>\n");
        }

        // ---- Scanner Results ----
        if (scan != null) {
            html.append("<h2>Vulnerability Scan Results</h2>\n");

            if (!scan.nucleiFindings().isEmpty()) {
                html.append("<h3>Nuclei Findings (").append(scan.nucleiFindings().size()).append(")</h3>\n");
                html.append("<pre class='output'>\n");
                for (String s : scan.nucleiFindings()) html.append(escHtml(s)).append("\n");
                html.append("</pre>\n");
            }

            if (!scan.dalfoxFindings().isEmpty()) {
                html.append("<h3>XSS Findings - Dalfox (").append(scan.dalfoxFindings().size()).append(")</h3>\n");
                html.append("<pre class='output'>\n");
                for (String s : scan.dalfoxFindings()) html.append(escHtml(s)).append("\n");
                html.append("</pre>\n");
            }

            if (!scan.sqlmapFindings().isEmpty()) {
                html.append("<h3>SQL Injection - SQLMap (").append(scan.sqlmapFindings().size()).append(")</h3>\n");
                html.append("<pre class='output'>\n");
                for (String s : scan.sqlmapFindings()) html.append(escHtml(s)).append("\n");
                html.append("</pre>\n");
            }

            if (!scan.niktoFindings().isEmpty()) {
                html.append("<h3>Web Server - Nikto (").append(scan.niktoFindings().size()).append(")</h3>\n");
                html.append("<pre class='output'>\n");
                for (String s : scan.niktoFindings()) html.append(escHtml(s)).append("\n");
                html.append("</pre>\n");
            }

            html.append("<h3>Scanner Tool Log</h3>\n<pre class='output'>\n");
            for (String s : scan.toolLog()) html.append(escHtml(s)).append("\n");
            html.append("</pre>\n");
        }

        html.append("<hr>\n<p class='footer'>Generated by burpinho v3.0.0 — Local AI Security Scanner</p>\n");
        html.append("</div>\n</body></html>");

        // Write to file
        try {
            new File(outputDir).mkdirs();
            try (FileWriter writer = new FileWriter(filepath)) {
                writer.write(html.toString());
            }
            log.accept("Report saved to: " + filepath);
            return filepath;
        } catch (IOException e) {
            log.accept("Failed to write report: " + e.getMessage());
            api.logging().logToError("ReportModule: " + e.getMessage());
            return null;
        }
    }

    private String generateExecutiveSummary(ReconResult recon, ScanResult scan, Consumer<String> log) {
        if (!aiDispatcher.isAvailable()) {
            return "<h2>Executive Summary</h2>\n<p><em>AI not available — connect an AI provider for executive summary.</em></p>\n";
        }

        log.accept("Generating AI executive summary...");

        StringBuilder context = new StringBuilder();
        context.append("Generate an executive summary for this security assessment:\n\n");
        if (recon != null) {
            context.append("RECON: ").append(recon.subdomainCount()).append(" subdomains, ");
            context.append(recon.aliveCount()).append(" alive, ");
            context.append(recon.openPorts().size()).append(" port entries\n");
        }
        if (scan != null) {
            context.append("SCAN: ").append(scan.totalFindings()).append(" findings ");
            context.append("(nuclei: ").append(scan.nucleiFindings().size());
            context.append(", xss: ").append(scan.dalfoxFindings().size());
            context.append(", sqli: ").append(scan.sqlmapFindings().size()).append(")\n");
        }
        List<FindingRow> passive = findingsRegistry.snapshot();
        if (!passive.isEmpty()) {
            context.append("PASSIVE AI: ").append(passive.size()).append(" findings\n");
        }

        String systemPrompt = """
                You are burpinho report writer. Generate a concise executive summary
                for a security assessment. Include:
                1. Overall risk level (Critical/High/Medium/Low)
                2. Key findings overview
                3. Top 3 priorities to address
                4. Brief compliance implications
                
                Keep it to 3-5 paragraphs. Use HTML formatting (<p>, <strong>, <ul>, <li>).
                """;

        Optional<String> aiSummary = aiDispatcher.analyze(systemPrompt, context.toString());
        if (aiSummary.isPresent()) {
            return "<h2>Executive Summary</h2>\n" + aiSummary.get() + "\n";
        }
        return "<h2>Executive Summary</h2>\n<p><em>AI summary generation failed.</em></p>\n";
    }

    private String htmlHeader() {
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                <meta charset="UTF-8">
                <title>burpinho Security Report</title>
                <style>
                  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
                  .container { max-width: 1100px; margin: 0 auto; }
                  h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }
                  h2 { color: #f0883e; margin-top: 30px; border-bottom: 1px solid #30363d; padding-bottom: 5px; }
                  h3 { color: #8b949e; }
                  .subtitle { color: #8b949e; }
                  table { border-collapse: collapse; width: 100%; margin: 10px 0; }
                  th { background: #161b22; color: #58a6ff; padding: 10px; text-align: left; border: 1px solid #30363d; }
                  td { padding: 8px 10px; border: 1px solid #30363d; }
                  tr:hover { background: #161b22; }
                  .severity-high { border-left: 4px solid #f85149; }
                  .severity-medium { border-left: 4px solid #f0883e; }
                  .severity-low { border-left: 4px solid #3fb950; }
                  .severity-information { border-left: 4px solid #58a6ff; }
                  pre.output { background: #161b22; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; border: 1px solid #30363d; }
                  ul { padding-left: 20px; }
                  li { margin: 3px 0; }
                  .footer { color: #484f58; text-align: center; margin-top: 40px; font-size: 12px; }
                  hr { border: none; border-top: 1px solid #30363d; margin: 30px 0; }
                </style>
                </head>
                <body>
                """;
    }

    private static String escHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
