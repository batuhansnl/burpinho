package com.sn1persecurity.silentchain.bapp.modules.scanner;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.tools.ToolCommand;
import com.sn1persecurity.silentchain.bapp.tools.ToolCommand.OutputFormat;
import com.sn1persecurity.silentchain.bapp.tools.ToolRegistry;
import com.sn1persecurity.silentchain.bapp.tools.ToolResult;
import com.sn1persecurity.silentchain.bapp.tools.ToolRunner;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * SCANNER module — orchestrates real vulnerability scanning tools.
 *
 * Tools:
 *   1. nuclei  — template-based vulnerability scanning
 *   2. dalfox  — XSS detection
 *   3. sqlmap  — SQL injection detection
 *   4. nikto   — web server scanning
 *   5. ffuf    — directory/file fuzzing
 *
 * Each tool runs independently. Results are aggregated in ScanResult.
 */
public class ScannerModule {

    private final MontoyaApi api;
    private final ToolRunner runner;
    private final ToolRegistry registry;
    private volatile boolean cancelled = false;

    public ScannerModule(MontoyaApi api, ToolRunner runner, ToolRegistry registry) {
        this.api = api;
        this.runner = runner;
        this.registry = registry;
    }

    /**
     * Run full vulnerability scan on a target.
     *
     * @param target    target URL or domain
     * @param urls      list of URLs to scan (from recon or Burp sitemap)
     * @param progress  live status callback
     */
    public ScanResult runFullScan(String target, List<String> urls, Consumer<String> progress) {
        cancelled = false;
        ScanResult result = new ScanResult(target);
        Consumer<String> log = msg -> {
            if (progress != null) progress.accept(msg);
            api.logging().logToOutput("SCANNER [" + target + "]: " + msg);
        };

        log.accept("Starting vulnerability scan for: " + target);

        // ---- Step 1: Nuclei ----
        if (!cancelled) runNuclei(target, urls, result, log);

        // ---- Step 2: Dalfox (XSS) ----
        if (!cancelled) runDalfox(urls, result, log);

        // ---- Step 3: SQLMap ----
        if (!cancelled) runSqlmap(urls, result, log);

        // ---- Step 4: Nikto ----
        if (!cancelled) runNikto(target, result, log);

        // ---- Step 5: Ffuf (directory fuzzing) ----
        if (!cancelled) runFfuf(target, result, log);

        log.accept("Scan " + (cancelled ? "CANCELLED" : "COMPLETED") +
                " — " + result.totalFindings() + " total findings");

        return result;
    }

    /**
     * Run only nuclei scan (quick scan option).
     */
    public ScanResult runNucleiOnly(String target, List<String> urls, Consumer<String> progress) {
        cancelled = false;
        ScanResult result = new ScanResult(target);
        runNuclei(target, urls, result, progress != null ? progress : s -> {});
        return result;
    }

    public void cancel() {
        cancelled = true;
    }

    // ======== Individual tool runners ========================================

    private void runNuclei(String target, List<String> urls, ScanResult result, Consumer<String> log) {
        if (!registry.isInstalled("nuclei")) {
            result.logTool("nuclei", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running nuclei...");

        List<String> args = new ArrayList<>();
        args.add("nuclei");

        if (urls != null && !urls.isEmpty()) {
            // Pipe URLs into nuclei
            String input = String.join("\n", urls);
            args.addAll(List.of("-silent", "-json", "-severity", "info,low,medium,high,critical"));
            ToolResult tr = runner.runWithPipe("nuclei", args, input, 900);
            result.addNucleiFindings(tr.parsedLines());
            result.logTool("nuclei", tr.summary(), tr.durationMs());
        } else {
            // Single target
            args.addAll(List.of("-u", "https://" + target, "-silent", "-json",
                    "-severity", "info,low,medium,high,critical"));
            ToolResult tr = runner.run(new ToolCommand("nuclei", args, 900, OutputFormat.JSON));
            result.addNucleiFindings(tr.parsedLines());
            result.logTool("nuclei", tr.summary(), tr.durationMs());
        }
    }

    private void runDalfox(List<String> urls, ScanResult result, Consumer<String> log) {
        if (!registry.isInstalled("dalfox")) {
            result.logTool("dalfox", "not installed (skipped)", 0);
            return;
        }

        // Filter URLs that have query parameters (XSS candidates)
        List<String> xssTargets = new ArrayList<>();
        if (urls != null) {
            for (String url : urls) {
                if (url.contains("?") || url.contains("=")) {
                    xssTargets.add(url);
                }
            }
        }

        if (xssTargets.isEmpty()) {
            result.logTool("dalfox", "no URLs with parameters to test", 0);
            return;
        }

        log.accept("Running dalfox on " + xssTargets.size() + " URL(s) with parameters...");

        // Limit to first 20 URLs to avoid very long scans
        if (xssTargets.size() > 20) {
            xssTargets = xssTargets.subList(0, 20);
            log.accept("Limiting dalfox to first 20 URLs");
        }

        String input = String.join("\n", xssTargets);
        ToolResult tr = runner.runWithPipe("dalfox",
                List.of("dalfox", "pipe", "--silence", "--format", "json"),
                input, 600);
        result.addDalfoxFindings(tr.parsedLines());
        result.logTool("dalfox", tr.summary(), tr.durationMs());
    }

    private void runSqlmap(List<String> urls, ScanResult result, Consumer<String> log) {
        if (!registry.isInstalled("sqlmap")) {
            result.logTool("sqlmap", "not installed (skipped)", 0);
            return;
        }

        // Filter URLs with parameters (SQLi candidates)
        List<String> sqliTargets = new ArrayList<>();
        if (urls != null) {
            for (String url : urls) {
                if (url.contains("?") && url.contains("=")) {
                    sqliTargets.add(url);
                }
            }
        }

        if (sqliTargets.isEmpty()) {
            result.logTool("sqlmap", "no URLs with parameters to test", 0);
            return;
        }

        log.accept("Running sqlmap on " + Math.min(sqliTargets.size(), 5) + " URL(s)...");

        // Limit to first 5 URLs (sqlmap is slow)
        int limit = Math.min(sqliTargets.size(), 5);
        for (int i = 0; i < limit && !cancelled; i++) {
            String url = sqliTargets.get(i);
            log.accept("SQLMap testing: " + url);

            ToolResult tr = runner.run(new ToolCommand("sqlmap",
                    List.of("sqlmap", "-u", url,
                            "--batch",       // non-interactive
                            "--level=1",
                            "--risk=1",
                            "--smart",       // smart mode
                            "--output-dir=/tmp/burpinho-sqlmap"),
                    300, OutputFormat.TEXT));

            // Parse sqlmap output for findings
            for (String line : tr.parsedLines()) {
                if (line.contains("injectable") || line.contains("vulnerable") ||
                    line.contains("payload:") || line.contains("[CRITICAL]") ||
                    line.contains("[WARNING]")) {
                    result.addSqlmapFindings(List.of(line));
                }
            }
            result.logTool("sqlmap[" + i + "]", tr.summary(), tr.durationMs());
        }
    }

    private void runNikto(String target, ScanResult result, Consumer<String> log) {
        if (!registry.isInstalled("nikto")) {
            result.logTool("nikto", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running nikto...");
        ToolResult tr = runner.run(new ToolCommand("nikto",
                List.of("nikto", "-h", "https://" + target,
                        "-maxtime", "120s",
                        "-nointeractive"),
                180, OutputFormat.TEXT));

        // Parse nikto output for findings
        for (String line : tr.parsedLines()) {
            if (line.startsWith("+") && !line.startsWith("+-")) {
                result.addNiktoFindings(List.of(line));
            }
        }
        result.logTool("nikto", tr.summary(), tr.durationMs());
    }

    private void runFfuf(String target, ScanResult result, Consumer<String> log) {
        if (!registry.isInstalled("ffuf")) {
            result.logTool("ffuf", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running ffuf directory fuzzing...");

        // Use a built-in small wordlist or common paths
        // ffuf needs a wordlist — check for common ones
        String wordlist = findWordlist();
        if (wordlist == null) {
            result.logTool("ffuf", "no wordlist found (skipped)", 0);
            return;
        }

        ToolResult tr = runner.run(new ToolCommand("ffuf",
                List.of("ffuf",
                        "-u", "https://" + target + "/FUZZ",
                        "-w", wordlist,
                        "-mc", "200,201,301,302,307,401,403,405",
                        "-of", "json",
                        "-o", "/tmp/burpinho-ffuf.json",
                        "-t", "20",         // 20 threads
                        "-timeout", "5",
                        "-s"),              // silent mode
                300, OutputFormat.JSON));
        result.addFfufResults(tr.parsedLines());
        result.logTool("ffuf", tr.summary(), tr.durationMs());
    }

    /**
     * Try to find a common wordlist on the system.
     */
    private String findWordlist() {
        String[] candidates = {
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        };
        for (String path : candidates) {
            if (new java.io.File(path).exists()) {
                return path;
            }
        }
        return null;
    }
}
