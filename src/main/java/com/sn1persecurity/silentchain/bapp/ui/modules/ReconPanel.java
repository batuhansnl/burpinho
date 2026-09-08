package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.modules.recon.ReconModule;
import com.sn1persecurity.silentchain.bapp.modules.recon.ReconResult;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.theme.Theme;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

/**
 * UI panel for the RECON module.
 * Provides target input, start/cancel buttons, and results display.
 */
public class ReconPanel extends JPanel {

    private final MontoyaApi api;
    private final ReconModule reconModule;
    private final ThreadPool threadPool;
    private final ScanState scanState;

    private final JTextField targetField = new JTextField(30);
    private final JButton startBtn = new JButton("Start Recon");
    private final JButton cancelBtn = new JButton("Cancel");
    private final JLabel statusLabel = new JLabel("Ready");
    private final JProgressBar progressBar = new JProgressBar();

    private final DefaultTableModel subdomainModel;
    private final JTable subdomainTable;
    private final JTextArea outputArea;

    private volatile ReconResult lastResult;

    public ReconPanel(MontoyaApi api, ReconModule reconModule, ThreadPool threadPool, ScanState scanState) {
        this.api = api;
        this.reconModule = reconModule;
        this.threadPool = threadPool;
        this.scanState = scanState;

        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top: Target input ----
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        topPanel.add(new JLabel("Target Domain:"));
        targetField.setToolTipText("Enter target domain (e.g. example.com)");
        topPanel.add(targetField);

        startBtn.setBackground(Theme.ACCENT_BLUE);
        startBtn.setForeground(Color.WHITE);
        startBtn.setOpaque(true);
        startBtn.setBorderPainted(false);
        startBtn.addActionListener(e -> onStart());
        topPanel.add(startBtn);

        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> onCancel());
        topPanel.add(cancelBtn);

        topPanel.add(statusLabel);

        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);
        topPanel.add(progressBar);

        add(topPanel, BorderLayout.NORTH);

        // ---- Center: Split pane — subdomains table + raw output ----
        subdomainModel = new DefaultTableModel(new String[]{"#", "Subdomain", "Status"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        subdomainTable = new JTable(subdomainModel);
        subdomainTable.getColumnModel().getColumn(0).setMaxWidth(50);
        subdomainTable.getColumnModel().getColumn(2).setMaxWidth(100);

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setBackground(new Color(22, 27, 34));
        outputArea.setForeground(new Color(201, 209, 217));

        JSplitPane center = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(subdomainTable),
                new JScrollPane(outputArea));
        center.setResizeWeight(0.5);
        center.setDividerLocation(250);

        add(center, BorderLayout.CENTER);

        // ---- Bottom: Summary ----
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bottomPanel.setBorder(BorderFactory.createTitledBorder("Recon Summary"));
        bottomPanel.add(new JLabel("Subdomains: 0 | Alive: 0 | Ports: 0 | URLs: 0"));
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void onStart() {
        String target = targetField.getText().trim();
        if (target.isEmpty()) {
            statusLabel.setText("Enter a target domain!");
            return;
        }

        // Clean target (remove protocol if present)
        target = target.replaceFirst("^https?://", "").replaceFirst("/.*$", "");
        final String cleanTarget = target;

        startBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("Running recon...");
        outputArea.setText("");
        subdomainModel.setRowCount(0);

        scanState.info("burpinho [RECON]: Starting recon for " + cleanTarget);

        threadPool.submit(() -> {
            try {
                ReconResult result = reconModule.runFullRecon(cleanTarget, msg -> {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText(msg);
                        outputArea.append(msg + "\n");
                        outputArea.setCaretPosition(outputArea.getDocument().getLength());
                    });
                });

                lastResult = result;

                SwingUtilities.invokeLater(() -> {
                    // Populate subdomain table
                    subdomainModel.setRowCount(0);
                    int i = 1;
                    for (String sub : result.subdomains()) {
                        boolean alive = result.aliveDomains().contains(sub);
                        subdomainModel.addRow(new Object[]{i++, sub, alive ? "ALIVE" : "-"});
                    }

                    // Show full output
                    outputArea.append("\n" + result.toSummary());
                    outputArea.setCaretPosition(outputArea.getDocument().getLength());

                    statusLabel.setText("Recon complete: " + result.subdomainCount() + " subdomains, "
                            + result.aliveCount() + " alive");

                    scanState.info("burpinho [RECON]: Completed — " + result.subdomainCount()
                            + " subdomains, " + result.aliveCount() + " alive");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("Error: " + t.getMessage()));
                scanState.error("burpinho [RECON]: " + t.getMessage());
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
        reconModule.cancel();
        statusLabel.setText("Cancelling...");
        scanState.info("burpinho [RECON]: Cancelled by user");
    }

    /** Set target from context menu. */
    public void setTarget(String target) {
        targetField.setText(target);
    }

    /** Get last recon result for report generation. */
    public ReconResult getLastResult() {
        return lastResult;
    }
}
