package com.sn1persecurity.silentchain.bapp.modules.recon;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.tools.ToolCommand;
import com.sn1persecurity.silentchain.bapp.tools.ToolCommand.OutputFormat;
import com.sn1persecurity.silentchain.bapp.tools.ToolRegistry;
import com.sn1persecurity.silentchain.bapp.tools.ToolResult;
import com.sn1persecurity.silentchain.bapp.tools.ToolRunner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RECON module — orchestrates real CLI tools + pure Java native fallback engines.
 *
 * Pipeline order:
 *   1. Subdomain Enumeration: subfinder / amass / assetfinder (CLI) -> Fallback: HackerTarget + DNS Brute
 *   2. DNS Resolution: dnsx (CLI) -> Fallback: Multi-threaded Java DNS
 *   3. HTTP Probing: httpx (CLI) -> Fallback: Native Java HTTP Probe (title, server, status)
 *   4. Port Scanning: naabu (CLI) -> Fallback: Native Socket Port Scanner (top ports)
 *   5. WAF Detection: wafw00f (CLI) -> Fallback: Native Header Signature Analyzer
 *   6. Tech Fingerprinting: whatweb (CLI) -> Fallback: Native Header & HTML Signature Analyzer
 *   7. Web Crawling: katana (CLI)
 */
public class ReconModule {

    private final MontoyaApi api;
    private final ToolRunner runner;
    private final ToolRegistry registry;
    private volatile boolean cancelled = false;

    public ReconModule(MontoyaApi api, ToolRunner runner, ToolRegistry registry) {
        this.api = api;
        this.runner = runner;
        this.registry = registry;
    }

    /**
     * Run full recon pipeline against a target domain.
     *
     * @param target     target domain (e.g. "example.com")
     * @param progress   callback for live status updates (runs on worker thread)
     * @return           aggregated recon results
     */
    public ReconResult runFullRecon(String target, Consumer<String> progress) {
        cancelled = false;
        ReconResult result = new ReconResult(target);
        Consumer<String> log = msg -> {
            if (progress != null) progress.accept(msg);
            api.logging().logToOutput("RECON [" + target + "]: " + msg);
        };

        log.accept("Starting recon pipeline for: " + target);

        // ---- Step 1: Subdomain Enumeration ----
        boolean anyCliSubTool = false;
        if (!cancelled && registry.isInstalled("subfinder")) {
            runSubfinder(target, result, log);
            anyCliSubTool = true;
        }
        if (!cancelled && registry.isInstalled("amass")) {
            runAmass(target, result, log);
            anyCliSubTool = true;
        }
        if (!cancelled && registry.isInstalled("assetfinder")) {
            runAssetfinder(target, result, log);
            anyCliSubTool = true;
        }

        // Native fallback or supplemental passive recon if subdomains list is sparse
        if (!cancelled && (!anyCliSubTool || result.subdomains().isEmpty())) {
            log.accept("Running built-in passive subdomain discovery (HackerTarget & DNS wordlist)...");
            runBuiltinPassiveSubdomains(target, result, log);
        }

        log.accept("Total subdomains discovered: " + result.subdomainCount());

        // ---- Step 2: DNS Resolution ----
        if (!cancelled && !result.subdomains().isEmpty()) {
            if (registry.isInstalled("dnsx")) {
                runDnsx(result, log);
            } else {
                log.accept("Running built-in multi-threaded DNS resolver...");
                runBuiltinDnsResolution(result, log);
            }
        }

        // ---- Step 3: HTTP Probing ----
        if (!cancelled) {
            List<String> toProbe = result.aliveDomains().isEmpty()
                    ? List.of(target)
                    : result.aliveDomains();

            if (registry.isInstalled("httpx")) {
                runHttpx(toProbe, result, log);
            } else {
                log.accept("Running built-in HTTP prober...");
                runBuiltinHttpProbe(toProbe, result, log);
            }
        }

        // ---- Step 4: Port Scanning ----
        if (!cancelled) {
            if (registry.isInstalled("naabu")) {
                runNaabu(target, result, log);
            } else {
                log.accept("Running built-in fast port scanner (top ports)...");
                runBuiltinPortScanner(target, result, log);
            }
        }

        // ---- Step 5: WAF Detection ----
        if (!cancelled) {
            if (registry.isInstalled("wafw00f")) {
                runWafw00f(target, result, log);
            } else {
                log.accept("Running built-in WAF signature detector...");
                runBuiltinWafDetector(target, result, log);
            }
        }

        // ---- Step 6: Tech Fingerprinting ----
        if (!cancelled) {
            if (registry.isInstalled("whatweb")) {
                runWhatweb(target, result, log);
            } else {
                log.accept("Running built-in technology fingerprinting...");
                runBuiltinTechDetector(target, result, log);
            }
        }

        // ---- Step 7: Web Crawling ----
        if (!cancelled && registry.isInstalled("katana")) {
            runKatana(target, result, log);
        }

        log.accept("Recon pipeline " + (cancelled ? "CANCELLED" : "COMPLETED") +
                " — " + result.subdomainCount() + " subdomains, " +
                result.aliveCount() + " alive, " +
                result.openPorts().size() + " port entries");

        return result;
    }

    /** Cancel a running recon. */
    public void cancel() {
        cancelled = true;
    }

    // ======== CLI Tool Runners ===============================================

    private void runSubfinder(String target, ReconResult result, Consumer<String> log) {
        log.accept("Running subfinder (CLI)...");
        ToolResult tr = runner.run(new ToolCommand("subfinder",
                List.of("subfinder", "-d", target, "-silent", "-all"),
                300, OutputFormat.TEXT));
        result.addSubdomains(tr.parsedLines());
        result.logTool("subfinder", tr.summary(), tr.durationMs());
    }

    private void runAmass(String target, ReconResult result, Consumer<String> log) {
        log.accept("Running amass passive (CLI)...");
        ToolResult tr = runner.run(new ToolCommand("amass",
                List.of("amass", "enum", "-passive", "-d", target),
                600, OutputFormat.TEXT));
        result.addSubdomains(tr.parsedLines());
        result.logTool("amass", tr.summary(), tr.durationMs());
    }

    private void runAssetfinder(String target, ReconResult result, Consumer<String> log) {
        log.accept("Running assetfinder (CLI)...");
        ToolResult tr = runner.run(new ToolCommand("assetfinder",
                List.of("assetfinder", "--subs-only", target),
                120, OutputFormat.TEXT));
        result.addSubdomains(tr.parsedLines());
        result.logTool("assetfinder", tr.summary(), tr.durationMs());
    }

    private void runDnsx(ReconResult result, Consumer<String> log) {
        log.accept("Running dnsx on " + result.subdomainCount() + " subdomains (CLI)...");
        String input = String.join("\n", result.subdomains());
        ToolResult tr = runner.runWithPipe("dnsx",
                List.of("dnsx", "-silent", "-resp"),
                input, 120);
        result.addAliveDomains(tr.parsedLines());
        result.logTool("dnsx", tr.summary(), tr.durationMs());
    }

    private void runHttpx(List<String> domains, ReconResult result, Consumer<String> log) {
        log.accept("Running httpx on " + domains.size() + " domain(s) (CLI)...");
        String input = String.join("\n", domains);
        ToolResult tr = runner.runWithPipe("httpx",
                List.of("httpx", "-silent", "-json",
                        "-title", "-tech-detect", "-status-code",
                        "-content-length", "-web-server",
                        "-follow-redirects"),
                input, 300);
        result.addHttpServices(tr.parsedLines());
        result.logTool("httpx", tr.summary(), tr.durationMs());
    }

    private void runNaabu(String target, ReconResult result, Consumer<String> log) {
        log.accept("Running naabu port scanner (CLI)...");
        List<String> targets = result.aliveDomains().isEmpty()
                ? List.of(target)
                : new ArrayList<>(result.aliveDomains());

        if (targets.size() > 20) {
            targets = targets.subList(0, 20);
            log.accept("Limiting naabu to first 20 targets");
        }

        String input = String.join("\n", targets);
        ToolResult tr = runner.runWithPipe("naabu",
                List.of("naabu", "-silent", "-json", "-top-ports", "1000"),
                input, 600);
        result.addOpenPorts(tr.parsedLines());
        result.logTool("naabu", tr.summary(), tr.durationMs());
    }

    private void runWafw00f(String target, ReconResult result, Consumer<String> log) {
        log.accept("Running wafw00f (CLI)...");
        ToolResult tr = runner.run(new ToolCommand("wafw00f",
                List.of("wafw00f", "https://" + target, "-a"),
                60, OutputFormat.TEXT));
        result.addWafInfo(tr.parsedLines());
        result.logTool("wafw00f", tr.summary(), tr.durationMs());
    }

    private void runWhatweb(String target, ReconResult result, Consumer<String> log) {
        log.accept("Running whatweb (CLI)...");
        ToolResult tr = runner.run(new ToolCommand("whatweb",
                List.of("whatweb", "-q", "--log-json=-", "https://" + target),
                60, OutputFormat.JSON));
        result.addTechFingerprints(tr.parsedLines());
        result.logTool("whatweb", tr.summary(), tr.durationMs());
    }

    private void runKatana(String target, ReconResult result, Consumer<String> log) {
        log.accept("Running katana crawler (CLI)...");
        ToolResult tr = runner.run(new ToolCommand("katana",
                List.of("katana", "-u", "https://" + target,
                        "-silent", "-d", "3",
                        "-jc",
                        "-kf", "all"),
                300, OutputFormat.TEXT));
        result.addCrawledUrls(tr.parsedLines());
        result.logTool("katana", tr.summary(), tr.durationMs());
    }

    // ======== Pure Java Native Fallback Engines ==============================

    private void runBuiltinPassiveSubdomains(String target, ReconResult result, Consumer<String> log) {
        long start = System.currentTimeMillis();
        Set<String> discovered = Collections.newSetFromMap(new ConcurrentHashMap<>());

        // Always add target itself
        discovered.add(target);

        // 1. HackerTarget Host Search API
        try {
            URL url = new URI("https://api.hackertarget.com/hostsearch/?q=" + target).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            if (conn.getResponseCode() == 200) {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        String[] parts = line.split(",");
                        if (parts.length > 0 && parts[0].contains(".")) {
                            discovered.add(parts[0].trim().toLowerCase());
                        }
                    }
                }
            }
        } catch (Throwable t) {
            // Passive API fallback failed, continue
        }

        // 2. DNS Brute-force top 35 standard subdomains
        String[] commonPrefixes = {
            "www", "mail", "api", "admin", "dev", "stage", "staging", "test", "app", "vpn",
            "portal", "auth", "login", "beta", "corp", "cdn", "static", "m", "mobile", "docs",
            "git", "gitlab", "grafana", "kibana", "db", "mysql", "redis", "cloud", "ws",
            "gateway", "backend", "frontend", "proxy", "sso", "idp"
        };

        ExecutorService dnsPool = Executors.newFixedThreadPool(10);
        for (String prefix : commonPrefixes) {
            if (cancelled) break;
            final String sub = prefix + "." + target;
            dnsPool.submit(() -> {
                try {
                    InetAddress[] addrs = InetAddress.getAllByName(sub);
                    if (addrs != null && addrs.length > 0) {
                        discovered.add(sub);
                    }
                } catch (Throwable ignored) {}
            });
        }
        dnsPool.shutdown();
        try {
            dnsPool.awaitTermination(6, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {}

        List<String> list = new ArrayList<>(discovered);
        result.addSubdomains(list);
        long ms = System.currentTimeMillis() - start;
        result.logTool("builtin-subdomains", "found " + list.size() + " subdomains", ms);
        log.accept("Built-in subdomains discovery completed: " + list.size() + " subdomains found.");
    }

    private void runBuiltinDnsResolution(ReconResult result, Consumer<String> log) {
        long start = System.currentTimeMillis();
        List<String> subdomains = new ArrayList<>(result.subdomains());
        List<String> alive = Collections.synchronizedList(new ArrayList<>());

        ExecutorService pool = Executors.newFixedThreadPool(15);
        for (String sub : subdomains) {
            if (cancelled) break;
            pool.submit(() -> {
                try {
                    InetAddress addr = InetAddress.getByName(sub);
                    if (addr != null) {
                        alive.add(sub);
                    }
                } catch (Throwable ignored) {}
            });
        }
        pool.shutdown();
        try {
            pool.awaitTermination(15, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {}

        result.addAliveDomains(alive);
        long ms = System.currentTimeMillis() - start;
        result.logTool("builtin-dns", "resolved " + alive.size() + "/" + subdomains.size() + " alive hosts", ms);
        log.accept("Built-in DNS resolution completed: " + alive.size() + " alive hosts.");
    }

    private void runBuiltinHttpProbe(List<String> domains, ReconResult result, Consumer<String> log) {
        long start = System.currentTimeMillis();
        List<String> services = Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(10);

        int limit = Math.min(domains.size(), 30);
        for (int i = 0; i < limit && !cancelled; i++) {
            String domain = domains.get(i);
            pool.submit(() -> {
                for (String proto : List.of("https://", "http://")) {
                    try {
                        URL url = new URI(proto + domain).toURL();
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) burpinho/3.0");
                        conn.setConnectTimeout(4000);
                        conn.setReadTimeout(4000);
                        conn.setInstanceFollowRedirects(true);

                        int code = conn.getResponseCode();
                        String server = conn.getHeaderField("Server");
                        if (server == null) server = "-";

                        String title = "-";
                        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                            StringBuilder body = new StringBuilder();
                            String l;
                            while ((l = br.readLine()) != null && body.length() < 10000) {
                                body.append(l);
                            }
                            Matcher m = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE).matcher(body);
                            if (m.find()) {
                                title = m.group(1).trim();
                            }
                        } catch (Throwable ignored) {}

                        String entry = "[" + code + "] " + proto + domain + " | Title: " + title + " | Server: " + server;
                        services.add(entry);
                        break; // If HTTPS works, avoid duplicating on HTTP
                    } catch (Throwable ignored) {}
                }
            });
        }
        pool.shutdown();
        try {
            pool.awaitTermination(15, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {}

        result.addHttpServices(services);
        long ms = System.currentTimeMillis() - start;
        result.logTool("builtin-httpx", "probed " + services.size() + " HTTP services", ms);
        log.accept("Built-in HTTP probing completed: " + services.size() + " active endpoints.");
    }

    private void runBuiltinPortScanner(String target, ReconResult result, Consumer<String> log) {
        long start = System.currentTimeMillis();
        int[] topPorts = {21, 22, 25, 53, 80, 443, 3000, 3306, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017};
        List<String> open = Collections.synchronizedList(new ArrayList<>());

        ExecutorService pool = Executors.newFixedThreadPool(10);
        for (int port : topPorts) {
            if (cancelled) break;
            pool.submit(() -> {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(target, port), 600);
                    open.add(target + ":" + port + " (OPEN)");
                } catch (Throwable ignored) {}
            });
        }
        pool.shutdown();
        try {
            pool.awaitTermination(8, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {}

        result.addOpenPorts(open);
        long ms = System.currentTimeMillis() - start;
        result.logTool("builtin-naabu", "found " + open.size() + " open ports", ms);
        log.accept("Built-in Port Scan: " + open.size() + " open ports detected.");
    }

    private void runBuiltinWafDetector(String target, ReconResult result, Consumer<String> log) {
        long start = System.currentTimeMillis();
        List<String> wafs = new ArrayList<>();
        try {
            URL url = new URI("https://" + target).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 burpinho/3.0");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.connect();

            String server = conn.getHeaderField("Server");
            String cfRay = conn.getHeaderField("CF-RAY");
            String amzCf = conn.getHeaderField("x-amz-cf-id");
            String akamai = conn.getHeaderField("X-Akamai-Transformed");
            String sucuri = conn.getHeaderField("x-sucuri-id");

            if (cfRay != null || (server != null && server.toLowerCase().contains("cloudflare"))) {
                wafs.add("WAF: Cloudflare");
            }
            if (amzCf != null) {
                wafs.add("WAF: AWS CloudFront / AWS WAF");
            }
            if (akamai != null) {
                wafs.add("WAF: Akamai CDN / WAF");
            }
            if (sucuri != null) {
                wafs.add("WAF: Sucuri CloudProxy");
            }
            if (wafs.isEmpty()) {
                wafs.add("WAF: No generic WAF detected (Direct access or custom protection)");
            }
        } catch (Throwable t) {
            wafs.add("WAF: Scan skipped (Host unreachable on HTTPS)");
        }

        result.addWafInfo(wafs);
        long ms = System.currentTimeMillis() - start;
        result.logTool("builtin-waf", String.join(", ", wafs), ms);
        log.accept("Built-in WAF detection completed: " + String.join(", ", wafs));
    }

    private void runBuiltinTechDetector(String target, ReconResult result, Consumer<String> log) {
        long start = System.currentTimeMillis();
        List<String> techs = new ArrayList<>();
        try {
            URL url = new URI("https://" + target).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 burpinho/3.0");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            String server = conn.getHeaderField("Server");
            String powered = conn.getHeaderField("X-Powered-By");
            if (server != null) techs.add("Server: " + server);
            if (powered != null) techs.add("Framework/Tech: " + powered);

            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String l;
                while ((l = br.readLine()) != null && sb.length() < 10000) {
                    sb.append(l);
                }
                String body = sb.toString().toLowerCase();
                if (body.contains("wp-content")) techs.add("CMS: WordPress");
                if (body.contains("drupal")) techs.add("CMS: Drupal");
                if (body.contains("react")) techs.add("Frontend: React");
                if (body.contains("vue")) techs.add("Frontend: Vue.js");
                if (body.contains("next")) techs.add("Frontend: Next.js");
            } catch (Throwable ignored) {}

            if (techs.isEmpty()) {
                techs.add("Tech Stack: Standard HTTP Web Server");
            }
        } catch (Throwable t) {
            techs.add("Tech Stack: Unreachable");
        }

        result.addTechFingerprints(techs);
        long ms = System.currentTimeMillis() - start;
        result.logTool("builtin-whatweb", String.join(" | ", techs), ms);
        log.accept("Built-in Tech fingerprinting completed: " + String.join(" | ", techs));
    }
}
