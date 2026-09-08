package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.modules.scanner.ScannerModule;
import com.sn1persecurity.silentchain.bapp.modules.scanner.ScanResult;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.theme.Theme;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * UI panel for the SCANNER module.
 * Provides target input, tool selection, and vulnerability scan results.
 */
public class ScannerPanel extends JPanel {

    private final MontoyaApi api;
    private final ScannerModule scannerModule;
    private final ThreadPool threadPool;
    private final ScanState scanState;

    private final JTextField targetField = new JTextField(30);
    private final JTextArea urlsArea = new JTextArea(5, 40);
    private final JCheckBox nucleiCb = new JCheckBox("Nuclei", true);
    private final JCheckBox dalfoxCb = new JCheckBox("Dalfox (XSS)", true);
    private final JCheckBox sqlmapCb = new JCheckBox("SQLMap", true);
    private final JCheckBox niktoCb = new JCheckBox("Nikto", true);
    private final JCheckBox ffufCb = new JCheckBox("Ffuf (Fuzzing)", false);
    private final JButton startBtn = new JButton("Start Scan");
    private final JButton cancelBtn = new JButton("Cancel");
    private final JLabel statusLabel = new JLabel("Ready");
    private final JProgressBar progressBar = new JProgressBar();
    private final JTextArea outputArea;

    private volatile ScanResult lastResult;

    public ScannerPanel(MontoyaApi api, ScannerModule scannerModule, ThreadPool threadPool, ScanState scanState) {
        this.api = api;
        this.scannerModule = scannerModule;
        this.threadPool = threadPool;
        this.scanState = scanState;

        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top: Target + Tools ----
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));

        // Target row
        JPanel targetRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        targetRow.add(new JLabel("Target:"));
        targetField.setToolTipText("Target domain or URL");
        targetRow.add(targetField);
        topPanel.add(targetRow);

        // URLs input
        JPanel urlsPanel = new JPanel(new BorderLayout());
        urlsPanel.setBorder(BorderFactory.createTitledBorder("URLs to Scan (one per line, optional)"));
        urlsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        urlsPanel.add(new JScrollPane(urlsArea), BorderLayout.CENTER);
        urlsPanel.setPreferredSize(new Dimension(0, 100));
        topPanel.add(urlsPanel);

        // Tool selection row
        JPanel toolRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        toolRow.setBorder(BorderFactory.createTitledBorder("Tools"));
        toolRow.add(nucleiCb);
        toolRow.add(dalfoxCb);
        toolRow.add(sqlmapCb);
        toolRow.add(niktoCb);
        toolRow.add(ffufCb);
        topPanel.add(toolRow);

        // Buttons row
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        startBtn.setBackground(Theme.SCAN_GREEN);
        startBtn.setForeground(Color.WHITE);
        startBtn.setOpaque(true);
        startBtn.setBorderPainted(false);
        startBtn.addActionListener(e -> onStart());
        btnRow.add(startBtn);

        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> onCancel());
        btnRow.add(cancelBtn);

        btnRow.add(statusLabel);
        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);
        btnRow.add(progressBar);
        topPanel.add(btnRow);

        add(topPanel, BorderLayout.NORTH);

        // ---- Center: Output ----
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setBackground(new Color(22, 27, 34));
        outputArea.setForeground(new Color(201, 209, 217));
        add(new JScrollPane(outputArea), BorderLayout.CENTER);
    }

    private void onStart() {
        String target = targetField.getText().trim();
        if (target.isEmpty()) {
            statusLabel.setText("Enter a target!");
            return;
        }
        target = target.replaceFirst("^https?://", "").replaceFirst("/.*$", "");
        final String cleanTarget = target;

        // Parse URLs
        List<String> urls = new ArrayList<>();
        for (String line : urlsArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) urls.add(trimmed);
        }

        startBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("Scanning...");
        outputArea.setText("");

        scanState.info("burpinho [SCANNER]: Starting scan for " + cleanTarget);

        threadPool.submit(() -> {
            try {
                ScanResult result = scannerModule.runFullScan(cleanTarget, urls, msg -> {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText(msg);
                        outputArea.append(msg + "\n");
                        outputArea.setCaretPosition(outputArea.getDocument().getLength());
                    });
                });

                lastResult = result;

                SwingUtilities.invokeLater(() -> {
                    outputArea.append("\n" + result.toSummary());
                    outputArea.setCaretPosition(outputArea.getDocument().getLength());
                    statusLabel.setText("Scan complete: " + result.totalFindings() + " findings");
                    scanState.info("burpinho [SCANNER]: Completed — " + result.totalFindings() + " findings");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("Error: " + t.getMessage()));
                scanState.error("burpinho [SCANNER]: " + t.getMessage());
            } finally {
                SwingUtilities.invokeLater(() -> {
                    startBtn.setEnabled(true);
                    cancelBtn.setEnabled(false);
                    progressBar.setVisible(false);
                });
            }
        });
    }

    private void onCancel() {
        scannerModule.cancel();
        statusLabel.setText("Cancelling...");
    }

    public void setTarget(String target) { targetField.setText(target); }
    public void addUrls(List<String> urls) {
        for (String u : urls) urlsArea.append(u + "\n");
    }
    public ScanResult getLastResult() { return lastResult; }
}
