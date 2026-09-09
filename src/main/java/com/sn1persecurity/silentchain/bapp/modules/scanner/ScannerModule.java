package com.sn1persecurity.silentchain.bapp.modules.scanner;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.tools.ToolCommand;
import com.sn1persecurity.silentchain.bapp.tools.ToolCommand.OutputFormat;
import com.sn1persecurity.silentchain.bapp.tools.ToolRegistry;
import com.sn1persecurity.silentchain.bapp.tools.ToolResult;
import com.sn1persecurity.silentchain.bapp.tools.ToolRunner;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * SCANNER module — orchestrates real CLI tools (Nuclei, Dalfox, SQLMap, Nikto, Ffuf)
 * + built-in fallback security scanners when CLI tools are not installed.
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
        if (!cancelled && registry.isInstalled("nuclei")) {
            runNuclei(target, urls, result, log);
        } else if (!cancelled) {
            log.accept("Nuclei CLI tool missing — using built-in sensitive paths check.");
            runBuiltinSensitiveFileScanner(target, result, log);
        }

        // ---- Step 2: Dalfox (XSS) ----
        if (!cancelled) {
            if (registry.isInstalled("dalfox")) {
                runDalfox(urls, result, log);
            } else {
                log.accept("Running built-in XSS reflection probe analyzer...");
                runBuiltinXssScanner(urls, result, log);
            }
        }

        // ---- Step 3: SQLMap ----
        if (!cancelled) {
            if (registry.isInstalled("sqlmap")) {
                runSqlmap(urls, result, log);
            } else {
                log.accept("Running built-in SQL Injection error probe analyzer...");
                runBuiltinSqliScanner(urls, result, log);
            }
        }

        // ---- Step 4: Nikto ----
        if (!cancelled) {
            if (registry.isInstalled("nikto")) {
                runNikto(target, result, log);
            } else {
                runBuiltinSensitiveFileScanner(target, result, log);
            }
        }

        // ---- Step 5: Ffuf (directory fuzzing) ----
        if (!cancelled && registry.isInstalled("ffuf")) {
            runFfuf(target, result, log);
        }

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
        if (registry.isInstalled("nuclei")) {
            runNuclei(target, urls, result, progress != null ? progress : s -> {});
        } else {
            runBuiltinSensitiveFileScanner(target, result, progress != null ? progress : s -> {});
        }
        return result;
    }

    public void cancel() {
        cancelled = true;
    }

    // ======== CLI Tool Runners ===============================================

    private void runNuclei(String target, List<String> urls, ScanResult result, Consumer<String> log) {
        log.accept("Running Nuclei scanner (CLI)...");

        List<String> args = new ArrayList<>();
        args.add("nuclei");

        if (urls != null && !urls.isEmpty()) {
            String input = String.join("\n", urls);
            args.addAll(List.of("-silent", "-json", "-severity", "info,low,medium,high,critical"));
            ToolResult tr = runner.runWithPipe("nuclei", args, input, 900);
            result.addNucleiFindings(tr.parsedLines());
            result.logTool("nuclei", tr.summary(), tr.durationMs());
        } else {
            String protoTarget = target.startsWith("http") ? target : "https://" + target;
            args.addAll(List.of("-u", protoTarget, "-silent", "-json",
                    "-severity", "info,low,medium,high,critical"));
            ToolResult tr = runner.run(new ToolCommand("nuclei", args, 900, OutputFormat.JSON));
            result.addNucleiFindings(tr.parsedLines());
            result.logTool("nuclei", tr.summary(), tr.durationMs());
        }
    }

    private void runDalfox(List<String> urls, ScanResult result, Consumer<String> log) {
        List<String> xssTargets = new ArrayList<>();
        if (urls != null) {
            for (String url : urls) {
                if (url.contains("?") && url.contains("=")) {
                    xssTargets.add(url);
                }
            }
        }

        if (xssTargets.isEmpty()) {
            result.logTool("dalfox", "no URLs with parameters to test", 0);
            return;
        }

        log.accept("Running dalfox on " + Math.min(xssTargets.size(), 20) + " URL(s)...");
        if (xssTargets.size() > 20) {
            xssTargets = xssTargets.subList(0, 20);
        }

        String input = String.join("\n", xssTargets);
        ToolResult tr = runner.runWithPipe("dalfox",
                List.of("dalfox", "pipe", "--silence", "--format", "json"),
                input, 600);
        result.addDalfoxFindings(tr.parsedLines());
        result.logTool("dalfox", tr.summary(), tr.durationMs());
    }

    private void runSqlmap(List<String> urls, ScanResult result, Consumer<String> log) {
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

        log.accept("Running sqlmap on " + Math.min(sqliTargets.size(), 3) + " URL(s)...");
        int limit = Math.min(sqliTargets.size(), 3);
        for (int i = 0; i < limit && !cancelled; i++) {
            String url = sqliTargets.get(i);
            ToolResult tr = runner.run(new ToolCommand("sqlmap",
                    List.of("sqlmap", "-u", url,
                            "--batch",
                            "--level=1",
                            "--risk=1",
                            "--smart"),
                    180, OutputFormat.TEXT));

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
        log.accept("Running nikto (CLI)...");
        ToolResult tr = runner.run(new ToolCommand("nikto",
                List.of("nikto", "-h", "https://" + target,
                        "-maxtime", "90s",
                        "-nointeractive"),
                120, OutputFormat.TEXT));

        for (String line : tr.parsedLines()) {
            if (line.startsWith("+") && !line.startsWith("+-")) {
                result.addNiktoFindings(List.of(line));
            }
        }
        result.logTool("nikto", tr.summary(), tr.durationMs());
    }

    private void runFfuf(String target, ScanResult result, Consumer<String> log) {
        log.accept("Running ffuf directory fuzzing (CLI)...");
        String wordlist = findWordlist();
        if (wordlist == null) {
            result.logTool("ffuf", "no wordlist found on system (skipped)", 0);
            return;
        }

        String protoTarget = target.startsWith("http") ? target : "https://" + target;
        ToolResult tr = runner.run(new ToolCommand("ffuf",
                List.of("ffuf",
                        "-u", protoTarget + "/FUZZ",
                        "-w", wordlist,
                        "-mc", "200,201,301,302,307,401,403,405",
                        "-t", "30",
                        "-timeout", "4",
                        "-s"),
                180, OutputFormat.JSON));
        result.addFfufResults(tr.parsedLines());
        result.logTool("ffuf", tr.summary(), tr.durationMs());
    }

    // ======== Built-in Fallback Security Scanners ============================

    private void runBuiltinSensitiveFileScanner(String target, ScanResult result, Consumer<String> log) {
        long start = System.currentTimeMillis();
        String base = (target.startsWith("http") ? target : "https://" + target).replaceAll("/+$", "");
        String[] sensitivePaths = {
            "/.env", "/.git/HEAD", "/robots.txt", "/swagger.json", "/openapi.json",
            "/api-docs", "/v2/api-docs", "/v3/api-docs", "/actuator/health",
            "/.DS_Store", "/phpinfo.php", "/.well-known/security.txt", "/server-status",
            "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml"
        };

        List<String> findings = new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(8);

        for (String path : sensitivePaths) {
            if (cancelled) break;
            pool.submit(() -> {
                try {
                    URL url = new URI(base + path).toURL();
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestProperty("User-Agent", "Mozilla/5.0 burpinho/3.0");
                    conn.setConnectTimeout(3000);
                    conn.setReadTimeout(3000);
                    conn.setInstanceFollowRedirects(false);

                    int code = conn.getResponseCode();
                    if (code == 200) {
                        findings.add("[POTENTIAL EXPOSURE] Found: " + base + path + " (HTTP " + code + ")");
                    } else if (code == 403 || code == 401) {
                        findings.add("[RESTRICTED ACCESS] Exists: " + base + path + " (HTTP " + code + ")");
                    }
                } catch (Throwable ignored) {}
            });
        }
        pool.shutdown();
        try {
            pool.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {}

        result.addNiktoFindings(findings);
        long ms = System.currentTimeMillis() - start;
        result.logTool("builtin-file-scanner", "discovered " + findings.size() + " sensitive paths", ms);
        log.accept("Built-in Sensitive File scan completed: " + findings.size() + " paths detected.");
    }

    private void runBuiltinXssScanner(List<String> urls, ScanResult result, Consumer<String> log) {
        long start = System.currentTimeMillis();
        List<String> findings = new ArrayList<>();
        if (urls == null || urls.isEmpty()) {
            result.logTool("builtin-xss", "no URLs provided to test", 0);
            return;
        }

        String canary = "burpxss" + System.currentTimeMillis() + "<svg/onload=1>";
        int tested = 0;
        for (String rawUrl : urls) {
            if (cancelled || tested >= 15) break;
            if (!rawUrl.contains("?") || !rawUrl.contains("=")) continue;
            tested++;

            try {
                String testUrl = rawUrl.replaceAll("=([^&]*)", "=" + URLEncoder.encode(canary, StandardCharsets.UTF_8));
                URL u = new URI(testUrl).toURL();
                HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                conn.setRequestProperty("User-Agent", "Mozilla/5.0 burpinho/3.0");
                conn.setConnectTimeout(4000);
                conn.setReadTimeout(4000);

                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder body = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null && body.length() < 30000) {
                        body.append(line);
                    }
                    if (body.toString().contains(canary) || body.toString().contains("<svg/onload=1>")) {
                        findings.add("[REFLECTED XSS] Parameter reflected unencoded at: " + testUrl);
                    }
                }
            } catch (Throwable ignored) {}
        }

        result.addDalfoxFindings(findings);
        long ms = System.currentTimeMillis() - start;
        result.logTool("builtin-xss", "tested " + tested + " URLs, " + findings.size() + " reflections", ms);
        log.accept("Built-in XSS scan completed: " + findings.size() + " potential issues.");
    }

    private void runBuiltinSqliScanner(List<String> urls, ScanResult result, Consumer<String> log) {
        long start = System.currentTimeMillis();
        List<String> findings = new ArrayList<>();
        if (urls == null || urls.isEmpty()) {
            result.logTool("builtin-sqli", "no URLs provided to test", 0);
            return;
        }

        String[] errorSignatures = {
            "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite3",
            "ODBC Driver", "Unclosed quotation mark", "syntax error near"
        };

        String quotePayload = "'";
        int tested = 0;
        for (String rawUrl : urls) {
            if (cancelled || tested >= 10) break;
            if (!rawUrl.contains("?") || !rawUrl.contains("=")) continue;
            tested++;

            try {
                String testUrl = rawUrl.replaceAll("=([^&]*)", "=" + URLEncoder.encode(quotePayload, StandardCharsets.UTF_8));
                URL u = new URI(testUrl).toURL();
                HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                conn.setRequestProperty("User-Agent", "Mozilla/5.0 burpinho/3.0");
                conn.setConnectTimeout(4000);
                conn.setReadTimeout(4000);

                try (BufferedReader br = new BufferedReader(new InputStreamReader(
                        conn.getResponseCode() >= 400 ? conn.getErrorStream() : conn.getInputStream(),
                        StandardCharsets.UTF_8))) {
                    StringBuilder body = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null && body.length() < 30000) {
                        body.append(line);
                    }
                    String content = body.toString();
                    for (String sig : errorSignatures) {
                        if (content.contains(sig)) {
                            findings.add("[SQL ERROR DETECTED] Signature '" + sig + "' at: " + testUrl);
                            break;
                        }
                    }
                }
            } catch (Throwable ignored) {}
        }

        result.addSqlmapFindings(findings);
        long ms = System.currentTimeMillis() - start;
        result.logTool("builtin-sqli", "tested " + tested + " URLs, " + findings.size() + " SQL errors", ms);
        log.accept("Built-in SQLi scan completed: " + findings.size() + " potential issues.");
    }

    private String findWordlist() {
        String userHome = System.getProperty("user.home", "");
        String[] candidates = {
            "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            userHome + "/SecLists/Discovery/Web-Content/common.txt"
        };
        for (String path : candidates) {
            if (new File(path).exists()) {
                return path;
            }
        }
        return null;
    }
}
