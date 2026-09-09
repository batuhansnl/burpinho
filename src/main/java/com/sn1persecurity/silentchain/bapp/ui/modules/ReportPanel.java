package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.modules.ipscan.IpScanResult;
import com.sn1persecurity.silentchain.bapp.modules.recon.ReconResult;
import com.sn1persecurity.silentchain.bapp.modules.report.ReportModule;
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
 * Generates unified HTML & Markdown security reports aggregating Passive AI, Recon,
 * IP & Network scans, and Vulnerability findings.
 */
public class ReportPanel extends JPanel {

    private final MontoyaApi api;
    private final ReportModule reportModule;
    private final ThreadPool threadPool;
    private final ScanState scanState;
    private final Supplier<ReconResult> reconSupplier;
    private final Supplier<ScanResult> scanSupplier;
    private final Supplier<IpScanResult> ipScanSupplier;

    private final JTextField outputDirField;
    private final JButton generateBtn = new JButton("HTML Raporu Oluştur");
    private final JButton browseBtn = new JButton("Gözat...");
    private final JLabel statusLabel = new JLabel("Hazır");
    private final JTextArea previewArea;

    public ReportPanel(MontoyaApi api, ReportModule reportModule, ThreadPool threadPool,
                       ScanState scanState,
                       Supplier<ReconResult> reconSupplier,
                       Supplier<ScanResult> scanSupplier,
                       Supplier<IpScanResult> ipScanSupplier) {
        this.api = api;
        this.reportModule = reportModule;
        this.threadPool = threadPool;
        this.scanState = scanState;
        this.reconSupplier = reconSupplier;
        this.scanSupplier = scanSupplier;
        this.ipScanSupplier = ipScanSupplier;

        setLayout(new BorderLayout(0, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top: Controls ----
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        topPanel.add(new JLabel("Çıktı Dizini:"));
        String defaultDir = System.getProperty("user.home") + File.separator + "burpinho-reports";
        outputDirField = new JTextField(defaultDir, 28);
        topPanel.add(outputDirField);

        browseBtn.addActionListener(e -> onBrowse());
        topPanel.add(browseBtn);

        generateBtn.setBackground(Theme.ACCENT_ORANGE);
        generateBtn.setForeground(Color.WHITE);
        generateBtn.setOpaque(true);
        generateBtn.setBorderPainted(false);
        generateBtn.setFont(generateBtn.getFont().deriveFont(Font.BOLD));
        generateBtn.addActionListener(e -> onGenerate());
        topPanel.add(generateBtn);

        topPanel.add(Box.createHorizontalStrut(8));
        topPanel.add(statusLabel);

        add(topPanel, BorderLayout.NORTH);

        // ---- Center: Preview ----
        previewArea = new JTextArea();
        previewArea.setEditable(false);
        previewArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        previewArea.setBackground(new Color(22, 27, 34));
        previewArea.setForeground(new Color(201, 209, 217));
        previewArea.setText("⚡ burpinho Birleşik Güvenlik Denetim Raporu Oluşturucu\n\n" +
                "Tüm modüllerden toplanan bulgularla yönetici güvenlik raporu oluşturmak için 'HTML Raporu Oluştur' butonuna tıklayın:\n\n" +
                "  • AI Pasif Analiz Bulguları (Gerçek zamanlı trafik denetleyicisi)\n" +
                "  • Subdomain & DNS Keşfi (Çözümlenen IP'ler, Açık Portlar, HTTP durumları)\n" +
                "  • IP & CIDR Ağ Tarama Sonuçları (PTR Hostname'leri, Servisler, Gecikmeler)\n" +
                "  • Güvenlik Açığı Tarama Bulguları (Nuclei CVE'leri, Hassas Yollar, CORS & Başlıklar)\n" +
                "  • XSS & SQLi Aktif Test Sonuçları\n" +
                "  • Yönetici Özeti (AI tarafından oluşturulan risk özeti ve iyileştirme yol haritası)\n");

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
        statusLabel.setText("Rapor oluşturuluyor...");
        previewArea.setText("");

        ReconResult recon = reconSupplier.get();
        ScanResult scan = scanSupplier.get();
        IpScanResult ipScan = ipScanSupplier != null ? ipScanSupplier.get() : null;
        String outputDir = outputDirField.getText().trim();

        scanState.info("burpinho [REPORT]: Generating unified security report...");

        threadPool.submit(() -> {
            try {
                String path = reportModule.generateReport(recon, scan, ipScan, outputDir, msg -> {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText(msg);
                        previewArea.append(msg + "\n");
                    });
                });

                SwingUtilities.invokeLater(() -> {
                    if (path != null) {
                        statusLabel.setText("✅ Rapor kaydedildi!");
                        previewArea.append("\n✅ Rapor başarıyla kaydedildi: " + path + "\n");
                        scanState.info("burpinho [REPORT]: Saved to " + path);

                        // Auto-open in system browser
                        try {
                            if (Desktop.isDesktopSupported()) {
                                Desktop.getDesktop().browse(new File(path).toURI());
                            }
                        } catch (Throwable ignored) {}
                    } else {
                        statusLabel.setText("❌ Rapor oluşturulamadı!");
                    }
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("❌ Hata: " + t.getMessage());
                    previewArea.append("Hata: " + t.getMessage() + "\n");
                });
            } finally {
                SwingUtilities.invokeLater(() -> generateBtn.setEnabled(true));
            }
        });
    }
}
