package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.modules.report.ReportModule;
import com.sn1persecurity.silentchain.bapp.modules.recon.ReconResult;
import com.sn1persecurity.silentchain.bapp.modules.scanner.ScanResult;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.theme.Theme;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.function.Supplier;

/**
 * UI panel for the REPORT module.
 * Generates HTML reports from Recon + Scanner + Passive AI results.
 */
public class ReportPanel extends JPanel {

    private final MontoyaApi api;
    private final ReportModule reportModule;
    private final ThreadPool threadPool;
    private final ScanState scanState;
    private final Supplier<ReconResult> reconSupplier;
    private final Supplier<ScanResult> scanSupplier;

    private final JTextField outputDirField;
    private final JButton generateBtn = new JButton("Generate Report");
    private final JButton browseBtn = new JButton("Browse...");
    private final JLabel statusLabel = new JLabel("Ready");
    private final JTextArea previewArea;

    public ReportPanel(MontoyaApi api, ReportModule reportModule, ThreadPool threadPool,
                       ScanState scanState,
                       Supplier<ReconResult> reconSupplier,
                       Supplier<ScanResult> scanSupplier) {
        this.api = api;
        this.reportModule = reportModule;
        this.threadPool = threadPool;
        this.scanState = scanState;
        this.reconSupplier = reconSupplier;
        this.scanSupplier = scanSupplier;

        setLayout(new BorderLayout(0, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top: Controls ----
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        topPanel.add(new JLabel("Output Directory:"));
        String defaultDir = System.getProperty("user.home") + File.separator + "burpinho-reports";
        outputDirField = new JTextField(defaultDir, 30);
        topPanel.add(outputDirField);

        browseBtn.addActionListener(e -> onBrowse());
        topPanel.add(browseBtn);

        generateBtn.setBackground(Theme.ACCENT_ORANGE);
        generateBtn.setForeground(Color.WHITE);
        generateBtn.setOpaque(true);
        generateBtn.setBorderPainted(false);
        generateBtn.addActionListener(e -> onGenerate());
        topPanel.add(generateBtn);

        topPanel.add(statusLabel);

        add(topPanel, BorderLayout.NORTH);

        // ---- Center: Preview ----
        previewArea = new JTextArea();
        previewArea.setEditable(false);
        previewArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        previewArea.setBackground(new Color(22, 27, 34));
        previewArea.setForeground(new Color(201, 209, 217));
        previewArea.setText("Click 'Generate Report' to create an HTML report from all module results.\n\n" +
                "The report includes:\n" +
                "  - AI Passive Analysis Findings\n" +
                "  - Recon Results (subdomains, ports, WAF, tech stack)\n" +
                "  - Vulnerability Scan Results (nuclei, dalfox, sqlmap, nikto)\n" +
                "  - Executive Summary (AI-generated, if connected)\n");

        add(new JScrollPane(previewArea), BorderLayout.CENTER);
    }

    private void onBrowse() {
        JFileChooser chooser = new JFileChooser(outputDirField.getText());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            outputDirField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void onGenerate() {
        generateBtn.setEnabled(false);
        statusLabel.setText("Generating report...");
        previewArea.setText("");

        ReconResult recon = reconSupplier.get();
        ScanResult scan = scanSupplier.get();
        String outputDir = outputDirField.getText().trim();

        if (recon == null && scan == null) {
            previewArea.setText("No recon or scan results available.\nRun Recon or Scanner modules first, or generate a report with passive findings only.");
        }

        scanState.info("burpinho [REPORT]: Generating report...");

        threadPool.submit(() -> {
            try {
                String path = reportModule.generateReport(recon, scan, outputDir, msg -> {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText(msg);
                        previewArea.append(msg + "\n");
                    });
                });

                SwingUtilities.invokeLater(() -> {
                    if (path != null) {
                        statusLabel.setText("Report saved!");
                        previewArea.append("\nReport saved to: " + path + "\n");
                        scanState.info("burpinho [REPORT]: Saved to " + path);

                        // Try to open the report
                        try {
                            if (Desktop.isDesktopSupported()) {
                                Desktop.getDesktop().browse(new File(path).toURI());
                            }
                        } catch (Throwable t) {
                            // Ignore — user can open manually
                        }
                    } else {
                        statusLabel.setText("Report generation failed!");
                    }
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Error: " + t.getMessage());
                    previewArea.append("Error: " + t.getMessage() + "\n");
                });
            } finally {
                SwingUtilities.invokeLater(() -> generateBtn.setEnabled(true));
            }
        });
    }
}
