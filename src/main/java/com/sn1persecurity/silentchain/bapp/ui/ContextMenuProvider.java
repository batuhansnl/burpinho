package com.sn1persecurity.silentchain.bapp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.scan.AnalysisOrchestrator;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.modules.ReconPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.ScannerPanel;

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

    // Module panels (set after construction)
    private ReconPanel reconPanel;
    private ScannerPanel scannerPanel;

    public ContextMenuProvider(MontoyaApi api, AiService aiService,
                               AnalysisOrchestrator orchestrator, ScanState scanState) {
        this.api = api;
        this.aiService = aiService;
        this.orchestrator = orchestrator;
        this.scanState = scanState;
    }

    /** Wire module panels for context menu actions. */
    public void setModulePanels(ReconPanel recon, ScannerPanel scanner) {
        this.reconPanel = recon;
        this.scannerPanel = scanner;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = collectSelected(event);
        if (selected.isEmpty()) {
            return List.of();
        }

        JMenu menu = new JMenu("burpinho");

        // 1. AI Analyze (existing)
        JMenuItem analyzeItem = new JMenuItem("Analyze Request (AI)");
        analyzeItem.addActionListener(e -> dispatchAnalyze(selected));
        menu.add(analyzeItem);

        menu.addSeparator();

        // 2. Recon Target
        JMenuItem reconItem = new JMenuItem("Recon Target Domain");
        reconItem.addActionListener(e -> dispatchRecon(selected));
        menu.add(reconItem);

        // 3. Deep Scan
        JMenuItem scanItem = new JMenuItem("Deep Vulnerability Scan");
        scanItem.addActionListener(e -> dispatchScan(selected));
        menu.add(scanItem);

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
        if (reconPanel == null) {
            scanState.info("burpinho: Recon module not initialized.");
            return;
        }
        // Extract host from first selected request
        String host = extractHost(messages);
        if (host != null) {
            SwingUtilities.invokeLater(() -> reconPanel.setTarget(host));
            scanState.info("burpinho [context-menu]: Recon target set to " + host + " — switch to Recon tab to start.");
        }
    }

    private void dispatchScan(List<HttpRequestResponse> messages) {
        if (scannerPanel == null) {
            scanState.info("burpinho: Scanner module not initialized.");
            return;
        }
        // Extract URLs from selected requests
        List<String> urls = new ArrayList<>();
        String host = null;
        for (HttpRequestResponse rr : messages) {
            if (rr.request() != null) {
                urls.add(rr.request().url());
                if (host == null) {
                    host = extractHostFromUrl(rr.request().url());
                }
            }
        }
        final String finalHost = host;
        SwingUtilities.invokeLater(() -> {
            if (finalHost != null) scannerPanel.setTarget(finalHost);
            scannerPanel.addUrls(urls);
        });
        scanState.info("burpinho [context-menu]: " + urls.size() + " URL(s) added to Scanner — switch to Scanner tab to start.");
    }

    private String extractHost(List<HttpRequestResponse> messages) {
        for (HttpRequestResponse rr : messages) {
            if (rr.request() != null) {
                return extractHostFromUrl(rr.request().url());
            }
        }
        return null;
    }

    private String extractHostFromUrl(String url) {
        try {
            return new URI(url).getHost();
        } catch (Throwable t) {
            return null;
        }
    }
}

