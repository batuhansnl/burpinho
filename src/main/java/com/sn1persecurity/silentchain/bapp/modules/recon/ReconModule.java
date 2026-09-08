package com.sn1persecurity.silentchain.bapp.modules.recon;

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
 * RECON module — orchestrates real CLI tools for target reconnaissance.
 *
 * Pipeline order:
 *   1. subfinder / amass / assetfinder → subdomain enumeration
 *   2. dnsx → DNS resolution (alive domains)
 *   3. httpx → HTTP probe (title, status, tech)
 *   4. naabu → port scanning
 *   5. wafw00f → WAF detection
 *   6. whatweb → tech fingerprinting
 *   7. katana → web crawling
 *
 * Each step's output feeds into the next. Tools that aren't installed are
 * silently skipped. The module never blocks the EDT — always run via ThreadPool.
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
        if (!cancelled) runSubfinder(target, result, log);
        if (!cancelled) runAmass(target, result, log);
        if (!cancelled) runAssetfinder(target, result, log);

        log.accept("Total subdomains found: " + result.subdomainCount());

        // ---- Step 2: DNS Resolution ----
        if (!cancelled && !result.subdomains().isEmpty()) {
            runDnsx(result, log);
        }

        // ---- Step 3: HTTP Probing ----
        if (!cancelled) {
            // Probe subdomains if we have them, otherwise just the target
            List<String> toProbe = result.aliveDomains().isEmpty()
                    ? List.of(target)
                    : result.aliveDomains();
            runHttpx(toProbe, result, log);
        }

        // ---- Step 4: Port Scanning ----
        if (!cancelled) runNaabu(target, result, log);

        // ---- Step 5: WAF Detection ----
        if (!cancelled) runWafw00f(target, result, log);

        // ---- Step 6: Tech Fingerprinting ----
        if (!cancelled) runWhatweb(target, result, log);

        // ---- Step 7: Web Crawling ----
        if (!cancelled) runKatana(target, result, log);

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

    // ======== Individual tool runners ========================================

    private void runSubfinder(String target, ReconResult result, Consumer<String> log) {
        if (!registry.isInstalled("subfinder")) {
            result.logTool("subfinder", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running subfinder...");
        ToolResult tr = runner.run(new ToolCommand("subfinder",
                List.of("subfinder", "-d", target, "-silent", "-all"),
                300, OutputFormat.TEXT));
        result.addSubdomains(tr.parsedLines());
        result.logTool("subfinder", tr.summary(), tr.durationMs());
    }

    private void runAmass(String target, ReconResult result, Consumer<String> log) {
        if (!registry.isInstalled("amass")) {
            result.logTool("amass", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running amass (passive)...");
        ToolResult tr = runner.run(new ToolCommand("amass",
                List.of("amass", "enum", "-passive", "-d", target),
                600, OutputFormat.TEXT));
        result.addSubdomains(tr.parsedLines());
        result.logTool("amass", tr.summary(), tr.durationMs());
    }

    private void runAssetfinder(String target, ReconResult result, Consumer<String> log) {
        if (!registry.isInstalled("assetfinder")) {
            result.logTool("assetfinder", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running assetfinder...");
        ToolResult tr = runner.run(new ToolCommand("assetfinder",
                List.of("assetfinder", "--subs-only", target),
                120, OutputFormat.TEXT));
        result.addSubdomains(tr.parsedLines());
        result.logTool("assetfinder", tr.summary(), tr.durationMs());
    }

    private void runDnsx(ReconResult result, Consumer<String> log) {
        if (!registry.isInstalled("dnsx")) {
            result.logTool("dnsx", "not installed (skipped)", 0);
            // Fallback: treat all subdomains as alive
            result.addAliveDomains(result.subdomains());
            return;
        }
        log.accept("Running dnsx on " + result.subdomainCount() + " subdomains...");
        String input = String.join("\n", result.subdomains());
        ToolResult tr = runner.runWithPipe("dnsx",
                List.of("dnsx", "-silent", "-resp"),
                input, 120);
        result.addAliveDomains(tr.parsedLines());
        result.logTool("dnsx", tr.summary(), tr.durationMs());
    }

    private void runHttpx(List<String> domains, ReconResult result, Consumer<String> log) {
        if (!registry.isInstalled("httpx")) {
            result.logTool("httpx", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running httpx on " + domains.size() + " domain(s)...");
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
        if (!registry.isInstalled("naabu")) {
            result.logTool("naabu", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running naabu port scan...");

        // If we have subdomains, scan them; otherwise just the target
        List<String> targets = result.aliveDomains().isEmpty()
                ? List.of(target)
                : new ArrayList<>(result.aliveDomains());

        // Limit to first 20 targets to avoid long scans
        if (targets.size() > 20) {
            targets = targets.subList(0, 20);
            log.accept("Limiting naabu to first 20 targets");
        }

        String input = String.join("\n", targets);
        ToolResult tr = runner.runWithPipe("naabu",
                List.of("naabu", "-silent", "-json",
                        "-top-ports", "1000"),
                input, 600);
        result.addOpenPorts(tr.parsedLines());
        result.logTool("naabu", tr.summary(), tr.durationMs());
    }

    private void runWafw00f(String target, ReconResult result, Consumer<String> log) {
        if (!registry.isInstalled("wafw00f")) {
            result.logTool("wafw00f", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running wafw00f...");
        ToolResult tr = runner.run(new ToolCommand("wafw00f",
                List.of("wafw00f", "https://" + target, "-a"),
                60, OutputFormat.TEXT));
        result.addWafInfo(tr.parsedLines());
        result.logTool("wafw00f", tr.summary(), tr.durationMs());
    }

    private void runWhatweb(String target, ReconResult result, Consumer<String> log) {
        if (!registry.isInstalled("whatweb")) {
            result.logTool("whatweb", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running whatweb...");
        ToolResult tr = runner.run(new ToolCommand("whatweb",
                List.of("whatweb", "-q", "--log-json=-", "https://" + target),
                60, OutputFormat.JSON));
        result.addTechFingerprints(tr.parsedLines());
        result.logTool("whatweb", tr.summary(), tr.durationMs());
    }

    private void runKatana(String target, ReconResult result, Consumer<String> log) {
        if (!registry.isInstalled("katana")) {
            result.logTool("katana", "not installed (skipped)", 0);
            return;
        }
        log.accept("Running katana crawler...");
        ToolResult tr = runner.run(new ToolCommand("katana",
                List.of("katana", "-u", "https://" + target,
                        "-silent", "-d", "3",   // depth 3
                        "-jc",                   // JS crawling
                        "-kf", "all"),           // known file patterns
                300, OutputFormat.TEXT));
        result.addCrawledUrls(tr.parsedLines());
        result.logTool("katana", tr.summary(), tr.durationMs());
    }
}
