package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.modules.recon.ReconResult;
import com.sn1persecurity.silentchain.bapp.modules.scanner.ScanResult;
import com.sn1persecurity.silentchain.bapp.modules.scanner.ScannerModule;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.theme.Theme;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileWriter;
import java.util.List;

/**
 * UI panel for the Vulnerability Scanner module.
 * Executes Nuclei templates, sensitive file exposure, and CORS/header misconfiguration scans.
 */
public class VulnScannerPanel extends JPanel {

    private final MontoyaApi api;
    private final ScannerModule scannerModule;
    private final ThreadPool threadPool;
    private final ScanState scanState;

    private final JTextField targetField = new JTextField(24);
    private final JComboBox<String> scanModeCombo = new JComboBox<>(new String[]{
            "Tam Güvenlik Açığı Taraması (Nuclei + CVEs + Exposure + CORS)",
            "Sadece Hassas Dosyalar & API İfşası (50+ kontrol)",
            "Sadece CORS & Güvenlik Başlıkları Yapılandırma Hataları"
    });
    private final JButton startBtn = new JButton("Güvenlik Taramasını Başlat");
    private final JButton cancelBtn = new JButton("İptal Et");
    private final JButton clearBtn = new JButton("Temizle");
    private final JButton exportBtn = new JButton("CSV Dışa Aktar");
    private final JLabel statusLabel = new JLabel("Hazır");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel summaryLabel = new JLabel("Bulgular: 0 Critical | 0 High | 0 Medium | 0 Low / Info");

    private final DefaultTableModel findingsModel;
    private final JTable findingsTable;
    private final JTextArea logArea;

    private volatile ScanResult lastResult;

    public VulnScannerPanel(MontoyaApi api, ScannerModule scannerModule, ThreadPool threadPool, ScanState scanState) {
        this.api = api;
        this.scannerModule = scannerModule;
        this.threadPool = threadPool;
        this.scanState = scanState;

        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top Config Panel ----
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("Güvenlik Açığı Tarayıcı Yapılandırması"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("Hedef (URL/Domain):"), gbc);
        gbc.gridx = 1;
        targetField.setToolTipText("Hedef domain veya URL girin (örn: example.com veya https://example.com)");
        configPanel.add(targetField, gbc);

        gbc.gridx = 2;
        configPanel.add(new JLabel("Tarama Profili:"), gbc);
        gbc.gridx = 3;
        configPanel.add(scanModeCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 4;
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        startBtn.setBackground(Theme.ACCENT_BLUE);
        startBtn.setForeground(Color.WHITE);
        startBtn.setOpaque(true);
        startBtn.setBorderPainted(false);
        startBtn.setFont(startBtn.getFont().deriveFont(Font.BOLD));
        startBtn.addActionListener(e -> onStart());
        btnPanel.add(startBtn);

        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> onCancel());
        btnPanel.add(cancelBtn);

        clearBtn.addActionListener(e -> onClear());
        btnPanel.add(clearBtn);

        exportBtn.addActionListener(e -> onExportCsv());
        btnPanel.add(exportBtn);

        btnPanel.add(Box.createHorizontalStrut(8));
        btnPanel.add(statusLabel);

        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);
        btnPanel.add(progressBar);

        configPanel.add(btnPanel, gbc);
        add(configPanel, BorderLayout.NORTH);

        // ---- Center: Findings Table & Live Log ----
        String[] columnNames = {"#", "Severity", "Bulgu Türü", "Hedef URL / Endpoint", "Detaylar / İmza"};
        findingsModel = new DefaultTableModel(columnNames, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        findingsTable = new JTable(findingsModel);
        findingsTable.setRowSorter(new TableRowSorter<>(findingsModel));

        findingsTable.getColumnModel().getColumn(0).setMaxWidth(50);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(90);
        findingsTable.getColumnModel().getColumn(1).setMaxWidth(110);
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(260);
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(320);

        // Severity Color Renderer
        findingsTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                String sev = String.valueOf(value).toUpperCase();
                if (!isSelected) {
                    if (sev.contains("CRITICAL")) {
                        c.setForeground(new Color(248, 81, 73));
                        setFont(getFont().deriveFont(Font.BOLD));
                    } else if (sev.contains("HIGH")) {
                        c.setForeground(new Color(255, 110, 80));
                        setFont(getFont().deriveFont(Font.BOLD));
                    } else if (sev.contains("MEDIUM")) {
                        c.setForeground(new Color(240, 136, 62));
                        setFont(getFont().deriveFont(Font.BOLD));
                    } else {
                        c.setForeground(new Color(63, 185, 80));
                    }
                }
                return c;
            }
        });

        // Popup Menu
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyUrl = new JMenuItem("Hedef URL'yi Kopyala");
        copyUrl.addActionListener(e -> copySelectedCell(3));
        JMenuItem copyFinding = new JMenuItem("Bulgu Detaylarını Kopyala");
        copyFinding.addActionListener(e -> copySelectedCell(4));
        popupMenu.add(copyUrl);
        popupMenu.add(copyFinding);
        findingsTable.setComponentPopupMenu(popupMenu);

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setBackground(new Color(22, 27, 34));
        logArea.setForeground(new Color(201, 209, 217));

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder("Tespit Edilen Güvenlik Açıkları & İfşalar"));
        tablePanel.add(new JScrollPane(findingsTable), BorderLayout.CENTER);

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Canlı İstek & Tarama Denetim Günlüğü"));
        logPanel.add(new JScrollPane(logArea), BorderLayout.CENTER);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, logPanel);
        centerSplit.setResizeWeight(0.6);
        centerSplit.setDividerLocation(280);

        add(centerSplit, BorderLayout.CENTER);

        // ---- Bottom Summary Bar ----
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bottomPanel.setBorder(BorderFactory.createEtchedBorder());
        bottomPanel.add(summaryLabel);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void onStart() {
        String target = targetField.getText().trim();
        if (target.isEmpty()) {
            statusLabel.setText("⚠️ Bir hedef domain veya URL girin!");
            return;
        }

        startBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("Güvenlik açıkları taranıyor...");
        logArea.setText("");
        findingsModel.setRowCount(0);

        scanState.info("burpinho [VULN-SCAN]: Starting scan for " + target);

        threadPool.submit(() -> {
            try {
                ScanResult result = scannerModule.runFullScan(target, List.of(), msg -> {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText(msg);
                        logArea.append(msg + "\n");
                        logArea.setCaretPosition(logArea.getDocument().getLength());
                    });
                });

                lastResult = result;

                SwingUtilities.invokeLater(() -> {
                    populateFindings(result);
                    logArea.append("\n" + result.toSummary());
                    logArea.setCaretPosition(logArea.getDocument().getLength());

                    statusLabel.setText("✅ Tarama tamamlandı: " + result.totalFindings() + " toplam bulgu");
                    scanState.info("burpinho [VULN-SCAN]: Completed — " + result.totalFindings() + " findings");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("❌ Hata: " + t.getMessage()));
                scanState.error("burpinho [VULN-SCAN]: " + t.getMessage());
            } finally {
                SwingUtilities.invokeLater(() -> {
                    startBtn.setEnabled(true);
                    cancelBtn.setEnabled(false);
                    progressBar.setVisible(false);
                });
            }
        });
    }

    private void populateFindings(ScanResult result) {
        findingsModel.setRowCount(0);
        int i = 1;
        int crit = 0, high = 0, med = 0, low = 0;

        // Nuclei / Sensitive paths findings
        for (String f : result.nucleiFindings()) {
            String sev = "MEDIUM";
            if (f.contains("HIGH")) { sev = "HIGH"; high++; }
            else if (f.contains("CRITICAL")) { sev = "CRITICAL"; crit++; }
            else if (f.contains("MEDIUM")) { sev = "MEDIUM"; med++; }
            else { sev = "LOW"; low++; }

            findingsModel.addRow(new Object[]{i++, sev, "Sensitive Path / CVE", result.target(), f});
        }

        // Nikto / CORS
        for (String f : result.niktoFindings()) {
            String sev = "LOW";
            if (f.contains("CRITICAL")) { sev = "CRITICAL"; crit++; }
            else if (f.contains("MEDIUM")) { sev = "MEDIUM"; med++; }
            else low++;

            findingsModel.addRow(new Object[]{i++, sev, "Configuration / Header", result.target(), f});
        }

        summaryLabel.setText("Bulgular: " + crit + " Critical | " + high + " High | " + med + " Medium | " + low + " Low/Info");
    }

    private void onCancel() {
        scannerModule.cancel();
        statusLabel.setText("Tarama iptal ediliyor...");
        scanState.info("burpinho [VULN-SCAN]: Scan cancelled by user");
    }

    private void onClear() {
        findingsModel.setRowCount(0);
        logArea.setText("");
        statusLabel.setText("Hazır");
        summaryLabel.setText("Bulgular: 0 Critical | 0 High | 0 Medium | 0 Low / Info");
    }

    private void onExportCsv() {
        if (findingsModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "Dışa aktarılacak bulgu yok!", "CSV Dışa Aktar", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("vuln_scan_results_" + System.currentTimeMillis() + ".csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,Severity,FindingType,Target,Details\n");
                for (int r = 0; r < findingsModel.getRowCount(); r++) {
                    StringBuilder row = new StringBuilder();
                    for (int c = 0; c < findingsModel.getColumnCount(); c++) {
                        String cell = String.valueOf(findingsModel.getValueAt(r, c)).replace("\"", "\"\"");
                        row.append("\"").append(cell).append("\"");
                        if (c < findingsModel.getColumnCount() - 1) row.append(",");
                    }
                    fw.write(row.toString() + "\n");
                }
                JOptionPane.showMessageDialog(this, "Başarıyla dışa aktarıldı: " + f.getAbsolutePath(), "CSV Dışa Aktar", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Dışa aktarma başarısız: " + ex.getMessage(), "Hata", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void copySelectedCell(int col) {
        int row = findingsTable.getSelectedRow();
        if (row >= 0) {
            Object val = findingsTable.getValueAt(row, col);
            if (val != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(val.toString()), null);
            }
        }
    }

    public void setTarget(String target) {
        targetField.setText(target);
    }

    public ScanResult getLastResult() {
        return lastResult;
    }
}
