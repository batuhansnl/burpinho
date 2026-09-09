package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.modules.ipscan.IpHostEntry;
import com.sn1persecurity.silentchain.bapp.modules.ipscan.IpScanResult;
import com.sn1persecurity.silentchain.bapp.modules.ipscan.IpScannerModule;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * UI panel for the IP & Network Scanner module.
 * Provides target input (IP/Range/CIDR), Port Profile selection,
 * real-time Host Table, and socket audit log.
 */
public class IpScanPanel extends JPanel {

    private final MontoyaApi api;
    private final IpScannerModule ipScannerModule;
    private final ThreadPool threadPool;
    private final ScanState scanState;

    private final JTextField targetField = new JTextField(22);
    private final JComboBox<String> portProfileCombo = new JComboBox<>(new String[]{
            "En Kritik 25 Port",
            "Web Portları (80,443,8080,8443,8000,8888,3000,5000,9000)",
            "En Yaygın 100 Port",
            "Veritabanı Portları (1433,1521,3306,5432,6379,27017)",
            "Özel Portlar..."
    });
    private final JTextField customPortsField = new JTextField(12);
    private final JSpinner threadsSpinner = new JSpinner(new SpinnerNumberModel(25, 1, 100, 5));
    private final JSpinner timeoutSpinner = new JSpinner(new SpinnerNumberModel(500, 100, 5000, 100));

    private final JButton startBtn = new JButton("IP Taramasını Başlat");
    private final JButton cancelBtn = new JButton("İptal Et");
    private final JButton clearBtn = new JButton("Temizle");
    private final JButton exportBtn = new JButton("CSV Dışa Aktar");
    private final JLabel statusLabel = new JLabel("Hazır");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel summaryLabel = new JLabel("Taranan Hedef: 0 | Canlı Host: 0 | Keşfedilen Açık Port: 0");

    private final DefaultTableModel hostsModel;
    private final JTable hostsTable;
    private final JTextArea logArea;

    private volatile IpScanResult lastResult;

    public IpScanPanel(MontoyaApi api, IpScannerModule ipScannerModule, ThreadPool threadPool, ScanState scanState) {
        this.api = api;
        this.ipScannerModule = ipScannerModule;
        this.threadPool = threadPool;
        this.scanState = scanState;

        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top Control Panel ----
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("IP / CIDR & Port Tarayıcı Yapılandırması"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Target & Profiles
        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("Hedef (IP/CIDR/Aralık):"), gbc);
        gbc.gridx = 1;
        targetField.setToolTipText("ör. 192.168.1.1, 192.168.1.1-50, 10.0.0.0/24 veya domain.com");
        configPanel.add(targetField, gbc);

        gbc.gridx = 2;
        configPanel.add(new JLabel("Port Profili:"), gbc);
        gbc.gridx = 3;
        configPanel.add(portProfileCombo, gbc);

        gbc.gridx = 4;
        customPortsField.setToolTipText("Virgülle ayrılmış portlar, ör. 80,443,8080");
        customPortsField.setEnabled(false);
        configPanel.add(customPortsField, gbc);

        // Row 1: Threads, Timeout, Action buttons
        gbc.gridx = 0; gbc.gridy = 1;
        configPanel.add(new JLabel("İş Parçacığı (Threads):"), gbc);
        gbc.gridx = 1;
        JPanel tPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        tPanel.add(threadsSpinner);
        tPanel.add(new JLabel("Zaman Aşımı (ms):"));
        tPanel.add(timeoutSpinner);
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

        portProfileCombo.addActionListener(e -> {
            boolean isCustom = "Özel Portlar...".equals(portProfileCombo.getSelectedItem());
            customPortsField.setEnabled(isCustom);
        });

        add(configPanel, BorderLayout.NORTH);

        // ---- Center: Split Pane with Table & Audit Log ----
        String[] columnNames = {"#", "IP Adresi", "PTR Host Adı", "Açık Portlar", "HTTP Servisi / Başlık", "Gecikme", "Durum"};
        hostsModel = new DefaultTableModel(columnNames, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        hostsTable = new JTable(hostsModel);
        hostsTable.setRowSorter(new TableRowSorter<>(hostsModel));

        hostsTable.getColumnModel().getColumn(0).setMaxWidth(50);
        hostsTable.getColumnModel().getColumn(1).setPreferredWidth(140);
        hostsTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        hostsTable.getColumnModel().getColumn(3).setPreferredWidth(130);
        hostsTable.getColumnModel().getColumn(4).setPreferredWidth(260);
        hostsTable.getColumnModel().getColumn(5).setPreferredWidth(80);
        hostsTable.getColumnModel().getColumn(6).setMaxWidth(100);

        // Status renderer
        hostsTable.getColumnModel().getColumn(6).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    if ("ALIVE".equalsIgnoreCase(String.valueOf(value)) || "CANLI".equalsIgnoreCase(String.valueOf(value))) {
                        c.setForeground(new Color(63, 185, 80));
                        setFont(getFont().deriveFont(Font.BOLD));
                    } else {
                        c.setForeground(Color.GRAY);
                    }
                }
                return c;
            }
        });

        // Popup Menu
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyIp = new JMenuItem("IP Adresini Kopyala");
        copyIp.addActionListener(e -> copySelectedCell(1));
        JMenuItem copyHost = new JMenuItem("Host Adını Kopyala");
        copyHost.addActionListener(e -> copySelectedCell(2));
        popupMenu.add(copyIp);
        popupMenu.add(copyHost);
        hostsTable.setComponentPopupMenu(popupMenu);

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setBackground(new Color(22, 27, 34));
        logArea.setForeground(new Color(201, 209, 217));

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder("Keşfedilen IP Hostları & Port Servisleri"));
        tablePanel.add(new JScrollPane(hostsTable), BorderLayout.CENTER);

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Canlı Soket & İstek Günlüğü"));
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
            statusLabel.setText("⚠️ Bir IP, CIDR veya domain girin!");
            return;
        }

        List<Integer> ports = getSelectedPorts();
        if (ports.isEmpty()) {
            statusLabel.setText("⚠️ Geçerli port belirtilmedi!");
            return;
        }

        int threads = (int) threadsSpinner.getValue();
        int timeoutMs = (int) timeoutSpinner.getValue();

        startBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("Ağ taranıyor...");
        logArea.setText("");
        hostsModel.setRowCount(0);

        scanState.info("burpinho [IP-SCAN]: Starting scan for " + target);

        threadPool.submit(() -> {
            try {
                IpScanResult result = ipScannerModule.runScan(
                        target, ports, threads, timeoutMs,
                        msg -> SwingUtilities.invokeLater(() -> {
                            logArea.append(msg + "\n");
                            logArea.setCaretPosition(logArea.getDocument().getLength());
                        }),
                        host -> SwingUtilities.invokeLater(() -> addOrUpdateHostRow(host))
                );

                lastResult = result;

                SwingUtilities.invokeLater(() -> {
                    refreshAllHosts(result);
                    statusLabel.setText("✅ Tarama tamamlandı: " + result.totalAlive() + " canlı host bulundu");
                    scanState.info("burpinho [IP-SCAN]: Completed — " + result.totalAlive() + " alive hosts");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("❌ Hata: " + t.getMessage()));
                scanState.error("burpinho [IP-SCAN]: " + t.getMessage());
            } finally {
                SwingUtilities.invokeLater(() -> {
                    startBtn.setEnabled(true);
                    cancelBtn.setEnabled(false);
                    progressBar.setVisible(false);
                });
            }
        });
    }

    private synchronized void addOrUpdateHostRow(IpHostEntry host) {
        // Check if row exists
        for (int r = 0; r < hostsModel.getRowCount(); r++) {
            if (host.ip().equals(hostsModel.getValueAt(r, 1))) {
                hostsModel.setValueAt(host.hostname(), r, 2);
                hostsModel.setValueAt(host.getPortsString(), r, 3);
                hostsModel.setValueAt(host.httpService(), r, 4);
                hostsModel.setValueAt(host.responseTimeMs() > 0 ? host.responseTimeMs() + "ms" : "-", r, 5);
                hostsModel.setValueAt(host.isAlive() ? "ALIVE" : "-", r, 6);
                return;
            }
        }

        int index = hostsModel.getRowCount() + 1;
        hostsModel.addRow(new Object[]{
                index,
                host.ip(),
                host.hostname(),
                host.getPortsString(),
                host.httpService(),
                host.responseTimeMs() > 0 ? host.responseTimeMs() + "ms" : "-",
                host.isAlive() ? "ALIVE" : "-"
        });

        updateSummary();
    }

    private void refreshAllHosts(IpScanResult result) {
        hostsModel.setRowCount(0);
        int i = 1;
        int totalPorts = 0;
        for (IpHostEntry h : result.getAliveHosts()) {
            hostsModel.addRow(new Object[]{
                    i++,
                    h.ip(),
                    h.hostname(),
                    h.getPortsString(),
                    h.httpService(),
                    h.responseTimeMs() > 0 ? h.responseTimeMs() + "ms" : "-",
                    h.isAlive() ? "ALIVE" : "-"
            });
            totalPorts += h.openPorts().size();
        }
        summaryLabel.setText("Taranan Hedef: " + result.totalScanned() +
                " | Canlı Host: " + result.totalAlive() +
                " | Keşfedilen Açık Port: " + totalPorts +
                " | Süre: " + (result.totalDurationMs() / 1000.0) + "s");
    }

    private void updateSummary() {
        int alive = 0;
        for (int r = 0; r < hostsModel.getRowCount(); r++) {
            if ("ALIVE".equals(hostsModel.getValueAt(r, 6))) alive++;
        }
        summaryLabel.setText("Keşfedilen Canlı Host: " + alive + " | Tarama devam ediyor...");
    }

    private List<Integer> getSelectedPorts() {
        int profileIndex = portProfileCombo.getSelectedIndex();
        return switch (profileIndex) {
            case 0 -> List.of(21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3000, 3306, 3389, 5000, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017);
            case 1 -> List.of(80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000);
            case 2 -> {
                List<Integer> top100 = new ArrayList<>(Arrays.asList(
                        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179,
                        389, 443, 445, 465, 514, 515, 587, 636, 873, 990, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521,
                        1723, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375, 2376, 26379, 3000, 3128, 3306, 3389, 3690,
                        4000, 4040, 4443, 5000, 5432, 5672, 5900, 5984, 5985, 5986, 6000, 6379, 7000, 7001, 7077, 8000,
                        8008, 8080, 8081, 8088, 8090, 8443, 8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9443, 9999,
                        10000, 11211, 27017, 27018, 50000, 50070
                ));
                yield top100;
            }
            case 3 -> List.of(1433, 1521, 3306, 5432, 6379, 9042, 9200, 9300, 27017, 27018);
            case 4 -> parseCustomPorts(customPortsField.getText().trim());
            default -> List.of(80, 443, 8080, 8443);
        };
    }

    private List<Integer> parseCustomPorts(String txt) {
        List<Integer> list = new ArrayList<>();
        if (txt.isEmpty()) return list;
        for (String token : txt.split("[,;\\s]+")) {
            try {
                int p = Integer.parseInt(token.trim());
                if (p > 0 && p <= 65535) list.add(p);
            } catch (NumberFormatException ignored) {}
        }
        return list;
    }

    private void onCancel() {
        ipScannerModule.cancel();
        statusLabel.setText("Tarama iptal ediliyor...");
        scanState.info("burpinho [IP-SCAN]: IP scan cancelled by user");
    }

    private void onClear() {
        hostsModel.setRowCount(0);
        logArea.setText("");
        statusLabel.setText("Hazır");
        summaryLabel.setText("Taranan Hedef: 0 | Canlı Host: 0 | Keşfedilen Açık Port: 0");
    }

    private void onExportCsv() {
        if (hostsModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "Dışa aktarılacak host verisi yok!", "CSV Dışa Aktar", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("ip_scan_results_" + System.currentTimeMillis() + ".csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,IP,PTRHostname,OpenPorts,HTTPService,Latency,Status\n");
                for (int r = 0; r < hostsModel.getRowCount(); r++) {
                    StringBuilder row = new StringBuilder();
                    for (int c = 0; c < hostsModel.getColumnCount(); c++) {
                        String cell = String.valueOf(hostsModel.getValueAt(r, c)).replace("\"", "\"\"");
                        row.append("\"").append(cell).append("\"");
                        if (c < hostsModel.getColumnCount() - 1) row.append(",");
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
        int row = hostsTable.getSelectedRow();
        if (row >= 0) {
            Object val = hostsTable.getValueAt(row, col);
            if (val != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(val.toString()), null);
            }
        }
    }

    public void setTarget(String target) {
        targetField.setText(target);
    }

    public IpScanResult getLastResult() {
        return lastResult;
    }
}
