package com.sn1persecurity.silentchain.bapp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.scan.AnalysisOrchestrator;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.modules.ExploitPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.FuzzerPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.IpScanPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.JwtPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.ReconPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.SqliPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.VulnScannerPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.XssPanel;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final AiService aiService;
    private final AnalysisOrchestrator orchestrator;
    private final ScanState scanState;

    // Module panels
    private ReconPanel reconPanel;
    private IpScanPanel ipScanPanel;
    private VulnScannerPanel vulnScannerPanel;
    private XssPanel xssPanel;
    private SqliPanel sqliPanel;
    private FuzzerPanel fuzzerPanel;
    private ExploitPanel exploitPanel;
    private JwtPanel jwtPanel;

    public ContextMenuProvider(MontoyaApi api, AiService aiService,
                               AnalysisOrchestrator orchestrator, ScanState scanState) {
        this.api = api;
        this.aiService = aiService;
        this.orchestrator = orchestrator;
        this.scanState = scanState;
    }

    /** Wire all module panels for context menu actions. */
    public void setModulePanels(ReconPanel recon,
                                IpScanPanel ipScan,
                                VulnScannerPanel vulnScanner,
                                XssPanel xss,
                                SqliPanel sqli,
                                FuzzerPanel fuzzer,
                                ExploitPanel exploit,
                                JwtPanel jwt) {
        this.reconPanel = recon;
        this.ipScanPanel = ipScan;
        this.vulnScannerPanel = vulnScanner;
        this.xssPanel = xss;
        this.sqliPanel = sqli;
        this.fuzzerPanel = fuzzer;
        this.exploitPanel = exploit;
        this.jwtPanel = jwt;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = collectSelected(event);
        if (selected.isEmpty()) {
            return List.of();
        }

        JMenu menu = new JMenu("burpinho");

        // 1. AI Analyze
        JMenuItem analyzeItem = new JMenuItem("⚡ Analyze Request (AI)");
        analyzeItem.addActionListener(e -> dispatchAnalyze(selected));
        menu.add(analyzeItem);

        menu.addSeparator();

        // 2. Recon Target
        JMenuItem reconItem = new JMenuItem("🔍 Send Host to Recon (Subdomain & IP)");
        reconItem.addActionListener(e -> dispatchRecon(selected));
        menu.add(reconItem);

        // 3. IP / Network Scanner
        JMenuItem ipScanItem = new JMenuItem("🌐 Send Host to IP & Network Scanner");
        ipScanItem.addActionListener(e -> dispatchIpScan(selected));
        menu.add(ipScanItem);

        // 4. Vulnerability Scanner
        JMenuItem vulnScanItem = new JMenuItem("🛡️ Send URL to Vulnerability Scanner");
        vulnScanItem.addActionListener(e -> dispatchVulnScan(selected));
        menu.add(vulnScanItem);

        menu.addSeparator();

        // 5. XSS Analyzer
        JMenuItem xssItem = new JMenuItem("🧪 Send URL to XSS Analyzer");
        xssItem.addActionListener(e -> dispatchXss(selected));
        menu.add(xssItem);

        // 6. SQLi Analyzer
        JMenuItem sqliItem = new JMenuItem("💉 Send URL to SQLi Analyzer");
        sqliItem.addActionListener(e -> dispatchSqli(selected));
        menu.add(sqliItem);

        // 7. Path Fuzzer
        JMenuItem fuzzerItem = new JMenuItem("🎯 Send Base URL to Path Fuzzer");
        fuzzerItem.addActionListener(e -> dispatchFuzzer(selected));
        menu.add(fuzzerItem);

        // 8. Exploit & PoC Advisor
        JMenuItem exploitItem = new JMenuItem("💥 Send URL to Exploit & PoC Generator");
        exploitItem.addActionListener(e -> dispatchExploit(selected));
        menu.add(exploitItem);

        menu.addSeparator();

        // 9. JWT Attack
        JMenuItem jwtItem = new JMenuItem("🔐 Send to JWT Attacker (Auto-Detect)");
        jwtItem.addActionListener(e -> dispatchJwt(selected));
        menu.add(jwtItem);

        return List.of(menu);
    }

    private List<HttpRequestResponse> collectSelected(ContextMenuEvent event) {
        List<HttpRequestResponse> out = new ArrayList<>();
        event.messageEditorRequestResponse().ifPresent(editor -> out.add(editor.requestResponse()));
        out.addAll(event.selectedRequestResponses());
        return out;
    }

    private void dispatchAnalyze(List<HttpRequestResponse> messages) {
        if (!aiService.isAvailable()) {
            scanState.info("burpinho: AI provider not available. Configure in Settings.");
            return;
        }
        scanState.info("burpinho [context-menu]: dispatching " + messages.size() + " message(s) for AI analysis.");
        for (HttpRequestResponse rr : messages) {
            orchestrator.analyzeAsync(rr, "context-menu");
        }
    }

    private void dispatchRecon(List<HttpRequestResponse> messages) {
        if (reconPanel == null) return;
        String host = extractHost(messages);
        if (host != null) {
            SwingUtilities.invokeLater(() -> reconPanel.setTarget(host));
            scanState.info("burpinho [context-menu]: Target domain set to " + host + " in Recon tab.");
        }
    }

    private void dispatchIpScan(List<HttpRequestResponse> messages) {
        if (ipScanPanel == null) return;
        String host = extractHost(messages);
        if (host != null) {
            SwingUtilities.invokeLater(() -> ipScanPanel.setTarget(host));
            scanState.info("burpinho [context-menu]: Target host set to " + host + " in IP Scanner tab.");
        }
    }

    private void dispatchVulnScan(List<HttpRequestResponse> messages) {
        if (vulnScannerPanel == null) return;
        String url = extractFirstUrl(messages);
        if (url != null) {
            SwingUtilities.invokeLater(() -> vulnScannerPanel.setTarget(url));
            scanState.info("burpinho [context-menu]: Target set to " + url + " in Vulnerability Scanner tab.");
        }
    }

    private void dispatchXss(List<HttpRequestResponse> messages) {
        if (xssPanel == null) return;
        List<String> urls = extractAllUrls(messages);
        if (!urls.isEmpty()) {
            String combined = String.join("\n", urls);
            SwingUtilities.invokeLater(() -> xssPanel.setTarget(combined));
            scanState.info("burpinho [context-menu]: " + urls.size() + " URL(s) sent to XSS Analyzer tab.");
        }
    }

    private void dispatchSqli(List<HttpRequestResponse> messages) {
        if (sqliPanel == null) return;
        List<String> urls = extractAllUrls(messages);
        if (!urls.isEmpty()) {
            String combined = String.join("\n", urls);
            SwingUtilities.invokeLater(() -> sqliPanel.setTarget(combined));
            scanState.info("burpinho [context-menu]: " + urls.size() + " URL(s) sent to SQLi Analyzer tab.");
        }
    }

    private void dispatchFuzzer(List<HttpRequestResponse> messages) {
        if (fuzzerPanel == null) return;
        String url = extractFirstUrl(messages);
        if (url != null) {
            String base = url.split("\\?")[0].replaceAll("/[^/]*$", "") + "/FUZZ";
            SwingUtilities.invokeLater(() -> fuzzerPanel.setTarget(base));
            scanState.info("burpinho [context-menu]: Target pattern set to " + base + " in Fuzzer tab.");
        }
    }

    private void dispatchExploit(List<HttpRequestResponse> messages) {
        if (exploitPanel == null) return;
        String url = extractFirstUrl(messages);
        if (url != null) {
            SwingUtilities.invokeLater(() -> exploitPanel.setQuery("Web Vulnerability", url));
            scanState.info("burpinho [context-menu]: Target URL set to " + url + " in Exploit tab.");
        }
    }

    private void dispatchJwt(List<HttpRequestResponse> messages) {
        if (jwtPanel == null) return;
        for (HttpRequestResponse rr : messages) {
            if (rr.request() != null) {
                String rawRequest = rr.request().toString();
                String jwt = com.sn1persecurity.silentchain.bapp.modules.jwt.JwtToken.extractFromRequest(rawRequest);
                if (jwt != null) {
                    SwingUtilities.invokeLater(() -> jwtPanel.setToken(jwt));
                    scanState.info("burpinho [context-menu]: JWT token auto-detected and sent to JWT Attack tab.");
                    return;
                }
            }
        }
        // Fallback: send full request
        String url = extractFirstUrl(messages);
        if (url != null) {
            scanState.info("burpinho [context-menu]: No JWT detected in request. Open JWT tab and paste token manually.");
        }
    }

    private String extractHost(List<HttpRequestResponse> messages) {
        for (HttpRequestResponse rr : messages) {
            if (rr.request() != null) {
                return extractHostFromUrl(rr.request().url());
            }
        }
        return null;
    }

    private String extractFirstUrl(List<HttpRequestResponse> messages) {
        for (HttpRequestResponse rr : messages) {
            if (rr.request() != null) {
                return rr.request().url();
            }
        }
        return null;
    }

    private List<String> extractAllUrls(List<HttpRequestResponse> messages) {
        List<String> list = new ArrayList<>();
        for (HttpRequestResponse rr : messages) {
            if (rr.request() != null) {
                list.add(rr.request().url());
            }
        }
        return list;
    }

    private String extractHostFromUrl(String url) {
        try {
            return new URI(url).getHost();
        } catch (Throwable t) {
            return null;
        }
    }
}
