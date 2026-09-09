package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.theme.Theme;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
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

/**
 * Dedicated XSS Analyzer Panel.
 * Performs deep parameter reflection analysis, WAF canary detection, and polyglot context tests.
 */
public class XssPanel extends JPanel {

    private final MontoyaApi api;
    private final ThreadPool threadPool;
    private final ScanState scanState;
    private volatile boolean cancelled = false;

    private final JTextArea targetsArea = new JTextArea(3, 30);
    private final JComboBox<String> payloadPresetCombo = new JComboBox<>(new String[]{
            "Otomatik Polyglot & Canary Yansıma Analizi",
            "<svg/onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "Özel Canary Payload..."
    });
    private final JTextField customPayloadField = new JTextField(16);
    private final JSpinner threadsSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 50, 5));

    private final JButton startBtn = new JButton("XSS Taramasını Başlat");
    private final JButton cancelBtn = new JButton("İptal Et");
    private final JButton clearBtn = new JButton("Temizle");
    private final JButton exportBtn = new JButton("CSV Dışa Aktar");
    private final JLabel statusLabel = new JLabel("Hazır");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel summaryLabel = new JLabel("Doğrulanan XSS: 0 | Denetlenen Parametreler: 0");

    private final DefaultTableModel findingsModel;
    private final JTable findingsTable;
    private final JTextArea logArea;

    public XssPanel(MontoyaApi api, ThreadPool threadPool, ScanState scanState) {
        this.api = api;
        this.threadPool = threadPool;
        this.scanState = scanState;

        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top Config ----
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("Cross-Site Scripting (XSS) Motor Yapılandırması"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("Parametreli Hedef URL'ler:"), gbc);
        gbc.gridx = 1;
        targetsArea.setToolTipText("Parametre içeren bir veya birden fazla URL girin (örn: https://example.com/search?q=test&cat=1)");
        configPanel.add(new JScrollPane(targetsArea), gbc);

        gbc.gridx = 2;
        configPanel.add(new JLabel("Payload Şablonu:"), gbc);
        gbc.gridx = 3;
        configPanel.add(payloadPresetCombo, gbc);

        gbc.gridx = 4;
        customPayloadField.setToolTipText("Özel XSS canary payload'ı");
        customPayloadField.setEnabled(false);
        configPanel.add(customPayloadField, gbc);

        // Row 1: Threads & Buttons
        gbc.gridx = 0; gbc.gridy = 1;
        configPanel.add(new JLabel("Threads:"), gbc);
        gbc.gridx = 1;
        JPanel tPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        tPanel.add(threadsSpinner);
        configPanel.add(tPanel, gbc);

        gbc.gridx = 2; gbc.gridwidth = 3;
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

        payloadPresetCombo.addActionListener(e -> {
            boolean isCustom = "Özel Canary Payload...".equals(payloadPresetCombo.getSelectedItem());
            customPayloadField.setEnabled(isCustom);
        });

        add(configPanel, BorderLayout.NORTH);

        // ---- Center: Table & Live Log Split Pane ----
        String[] columnNames = {"#", "Severity", "Hedef URL", "Parametre", "Kullanılan Payload", "Yansıma Durumu", "Durum"};
        findingsModel = new DefaultTableModel(columnNames, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        findingsTable = new JTable(findingsModel);
        findingsTable.setRowSorter(new TableRowSorter<>(findingsModel));

        findingsTable.getColumnModel().getColumn(0).setMaxWidth(50);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(90);
        findingsTable.getColumnModel().getColumn(1).setMaxWidth(110);
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(240);
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(180);
        findingsTable.getColumnModel().getColumn(5).setPreferredWidth(180);
        findingsTable.getColumnModel().getColumn(6).setMaxWidth(110);

        findingsTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    c.setForeground(new Color(248, 81, 73));
                    setFont(getFont().deriveFont(Font.BOLD));
                }
                return c;
            }
        });

        // Popup Menu
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyUrl = new JMenuItem("Zafiyetli URL'yi Kopyala");
        copyUrl.addActionListener(e -> copySelectedCell(2));
        JMenuItem copyPayload = new JMenuItem("Payload'ı Kopyala");
        copyPayload.addActionListener(e -> copySelectedCell(4));
        popupMenu.add(copyUrl);
        popupMenu.add(copyPayload);
        findingsTable.setComponentPopupMenu(popupMenu);

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setBackground(new Color(22, 27, 34));
        logArea.setForeground(new Color(201, 209, 217));

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder("Doğrulanan XSS Zafiyetleri"));
        tablePanel.add(new JScrollPane(findingsTable), BorderLayout.CENTER);

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("XSS Canlı Payload Enjeksiyonu & Yansıma Denetim Günlüğü"));
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
        String rawTargets = targetsArea.getText().trim();
        if (rawTargets.isEmpty()) {
            statusLabel.setText("⚠️ Parametre içeren en az bir URL girin!");
            return;
        }

        List<String> targetList = new ArrayList<>();
        for (String line : rawTargets.split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) targetList.add(trimmed);
        }

        int threads = (int) threadsSpinner.getValue();
        cancelled = false;

        startBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("XSS probları enjekte ediliyor...");
        logArea.setText("");
        findingsModel.setRowCount(0);

        scanState.info("burpinho [XSS]: Starting XSS reflection scans on " + targetList.size() + " URL(s)");

        threadPool.submit(() -> {
            try {
                runXssAudits(targetList, threads);
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("✅ XSS taraması tamamlandı.");
                    scanState.info("burpinho [XSS]: Scan finished.");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("❌ Hata: " + t.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> {
                    startBtn.setEnabled(true);
                    cancelBtn.setEnabled(false);
                    progressBar.setVisible(false);
                });
            }
        });
    }

    private void runXssAudits(List<String> targets, int threads) {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        int[] stats = new int[]{0, 0}; // [audited, confirmed]

        List<String> payloadsToTest = getPayloadsToTest();

        for (String rawUrl : targets) {
            if (cancelled) break;
            if (!rawUrl.contains("?") || !rawUrl.contains("=")) {
                log("[!] Atlanıyor (URL içinde parametre bulunamadı): " + rawUrl);
                continue;
            }

            pool.submit(() -> {
                for (String payload : payloadsToTest) {
                    if (cancelled) break;
                    stats[0]++;
                    log("[*] URL test ediliyor: " + rawUrl + " payload: " + payload);

                    try {
                        String testUrl = rawUrl.replaceAll("=([^&]*)", "=" + URLEncoder.encode(payload, StandardCharsets.UTF_8));
                        URL u = new URI(testUrl).toURL();
                        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) burpinho/4.0");
                        conn.setConnectTimeout(4500);
                        conn.setReadTimeout(4500);

                        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                                conn.getResponseCode() >= 400 ? conn.getErrorStream() : conn.getInputStream(),
                                StandardCharsets.UTF_8))) {
                            StringBuilder body = new StringBuilder();
                            String line;
                            while ((line = br.readLine()) != null && body.length() < 40000) {
                                body.append(line);
                            }
                            String resp = body.toString();

                            if (resp.contains(payload) || (payload.contains("<svg") && resp.contains("<svg/onload=1>"))) {
                                stats[1]++;
                                log("[+] [DOĞRULANMIŞ XSS ZAFIYETİ] Payload ham olarak yansıdı: " + testUrl);
                                SwingUtilities.invokeLater(() -> {
                                    int id = findingsModel.getRowCount() + 1;
                                    findingsModel.addRow(new Object[]{
                                            id, "HIGH", rawUrl, "QueryParam", payload, "Gövdede Filtresiz Yansıma", "VULNERABLE"
                                    });
                                    summaryLabel.setText("Doğrulanan XSS: " + stats[1] + " | Denetlenen Parametreler: " + stats[0]);
                                });
                                break;
                            } else {
                                log("[-] Yansımadı veya sanitize edildi: " + testUrl);
                            }
                        }
                    } catch (Throwable t) {
                        log("[!] İstek başarısız: " + t.getMessage());
                    }
                }
            });
        }

        pool.shutdown();
        try {
            pool.awaitTermination(15, TimeUnit.MINUTES);
        } catch (InterruptedException ignored) {}

        SwingUtilities.invokeLater(() -> {
            summaryLabel.setText("Doğrulanan XSS: " + stats[1] + " | Denetlenen Parametreler: " + stats[0]);
        });
    }

    private void getPayloadsToTestInternal() {}

    private List<String> getPayloadsToTest() {
        int idx = payloadPresetCombo.getSelectedIndex();
        String canary = "burpxss" + System.currentTimeMillis() + "<svg/onload=1>";
        return switch (idx) {
            case 0 -> List.of(canary, "><script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>");
            case 1 -> List.of("<svg/onload=alert(1)>");
            case 2 -> List.of("\"><script>alert(1)</script>");
            case 3 -> List.of("'\"><img src=x onerror=alert(1)>");
            case 4 -> List.of("javascript:alert(1)");
            case 5 -> {
                String c = customPayloadField.getText().trim();
                yield c.isEmpty() ? List.of(canary) : List.of(c);
            }
            default -> List.of(canary);
        };
    }

    private void log(String msg) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(msg + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("XSS: " + msg);
        }
    }

    private void onCancel() {
        cancelled = true;
        statusLabel.setText("XSS taraması iptal ediliyor...");
        scanState.info("burpinho [XSS]: Cancelled by user");
    }

    private void onClear() {
        findingsModel.setRowCount(0);
        logArea.setText("");
        statusLabel.setText("Hazır");
        summaryLabel.setText("Doğrulanan XSS: 0 | Denetlenen Parametreler: 0");
    }

    private void onExportCsv() {
        if (findingsModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "Dışa aktarılacak XSS bulgusu yok!", "CSV Dışa Aktar", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("xss_findings_" + System.currentTimeMillis() + ".csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,Severity,TargetURL,Parameter,Payload,ReflectionState,Status\n");
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
        targetsArea.setText(target);
    }
}
