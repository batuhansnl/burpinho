package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.modules.recon.ReconModule;
import com.sn1persecurity.silentchain.bapp.modules.recon.ReconResult;
import com.sn1persecurity.silentchain.bapp.modules.recon.SubdomainEntry;
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
 * Enhanced RECON UI panel with Subdomain, Resolved IP, Open Ports, HTTP metadata,
 * and live audit console.
 */
public class ReconPanel extends JPanel {

    private final MontoyaApi api;
    private final ReconModule reconModule;
    private final ThreadPool threadPool;
    private final ScanState scanState;

    private final JTextField targetField = new JTextField(24);
    private final JButton startBtn = new JButton("Tam Keşfi Başlat");
    private final JButton cancelBtn = new JButton("İptal Et");
    private final JButton clearBtn = new JButton("Temizle");
    private final JButton exportBtn = new JButton("CSV Dışa Aktar");
    private final JLabel statusLabel = new JLabel("Hazır");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel summaryLabel = new JLabel("Subdomain: 0 | Canlı Host: 0 | Toplam IP: 0 | Açık Port: 0");

    private final DefaultTableModel subdomainModel;
    private final JTable subdomainTable;
    private final TableRowSorter<DefaultTableModel> sorter;
    private final JTextArea outputArea;

    private volatile ReconResult lastResult;

    public ReconPanel(MontoyaApi api, ReconModule reconModule, ThreadPool threadPool, ScanState scanState) {
        this.api = api;
        this.reconModule = reconModule;
        this.threadPool = threadPool;
        this.scanState = scanState;

        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top Control Panel ----
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        topPanel.add(new JLabel("Hedef Domain:"));
        targetField.setToolTipText("Hedef domaini girin (ör. example.com)");
        topPanel.add(targetField);

        startBtn.setBackground(Theme.ACCENT_BLUE);
        startBtn.setForeground(Color.WHITE);
        startBtn.setOpaque(true);
        startBtn.setBorderPainted(false);
        startBtn.setFont(startBtn.getFont().deriveFont(Font.BOLD));
        startBtn.addActionListener(e -> onStart());
        topPanel.add(startBtn);

        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> onCancel());
        topPanel.add(cancelBtn);

        clearBtn.addActionListener(e -> onClear());
        topPanel.add(clearBtn);

        exportBtn.addActionListener(e -> onExportCsv());
        topPanel.add(exportBtn);

        topPanel.add(Box.createHorizontalStrut(10));
        topPanel.add(statusLabel);

        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);
        topPanel.add(progressBar);

        add(topPanel, BorderLayout.NORTH);

        // ---- Center: Subdomains Table + Live Log Split Pane ----
        String[] columnNames = {"#", "Subdomain", "Çözümlenen IP(ler)", "Açık Portlar", "HTTP Kodu", "Başlık / Web Sunucusu", "Durum"};
        subdomainModel = new DefaultTableModel(columnNames, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        subdomainTable = new JTable(subdomainModel);
        sorter = new TableRowSorter<>(subdomainModel);
        subdomainTable.setRowSorter(sorter);

        subdomainTable.getColumnModel().getColumn(0).setPreferredWidth(45);
        subdomainTable.getColumnModel().getColumn(0).setMaxWidth(60);
        subdomainTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        subdomainTable.getColumnModel().getColumn(2).setPreferredWidth(160);
        subdomainTable.getColumnModel().getColumn(3).setPreferredWidth(120);
        subdomainTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        subdomainTable.getColumnModel().getColumn(4).setMaxWidth(90);
        subdomainTable.getColumnModel().getColumn(5).setPreferredWidth(220);
        subdomainTable.getColumnModel().getColumn(6).setPreferredWidth(90);
        subdomainTable.getColumnModel().getColumn(6).setMaxWidth(110);

        // Status column renderer
        subdomainTable.getColumnModel().getColumn(6).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                String val = String.valueOf(value);
                if (!isSelected) {
                    if ("ALIVE".equalsIgnoreCase(val) || "CANLI".equalsIgnoreCase(val)) {
                        c.setForeground(new Color(63, 185, 80));
                        setFont(getFont().deriveFont(Font.BOLD));
                    } else {
                        c.setForeground(Color.GRAY);
                    }
                }
                return c;
            }
        });

        // Right-click context menu on table
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copySub = new JMenuItem("Subdomain'i Kopyala");
        copySub.addActionListener(e -> copySelectedCell(1));
        JMenuItem copyIp = new JMenuItem("IP Adresini Kopyala");
        copyIp.addActionListener(e -> copySelectedCell(2));
        popupMenu.add(copySub);
        popupMenu.add(copyIp);
        subdomainTable.setComponentPopupMenu(popupMenu);

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setBackground(new Color(22, 27, 34));
        outputArea.setForeground(new Color(201, 209, 217));

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder("Keşfedilen Subdomainler & Canlı Host Envanteri"));
        tablePanel.add(new JScrollPane(subdomainTable), BorderLayout.CENTER);

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Canlı Keşif Günlüğü"));
        logPanel.add(new JScrollPane(outputArea), BorderLayout.CENTER);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, logPanel);
        centerSplit.setResizeWeight(0.6);
        centerSplit.setDividerLocation(300);

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
            statusLabel.setText("⚠️ Lütfen bir hedef domain girin!");
            return;
        }

        // Clean domain
        target = target.replaceFirst("^https?://", "").replaceFirst("/.*$", "");
        final String cleanTarget = target;

        startBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("Keşif yapılıyor...");
        outputArea.setText("");
        subdomainModel.setRowCount(0);

        scanState.info("burpinho [RECON]: Starting full reconnaissance for " + cleanTarget);

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
                    refreshTableData(result);
                    outputArea.append("\n" + result.toSummary());
                    outputArea.setCaretPosition(outputArea.getDocument().getLength());

                    statusLabel.setText("✅ Keşif tamamlandı: " + result.subdomainCount() + " subdomain, " + result.aliveCount() + " canlı host");
                    scanState.info("burpinho [RECON]: Completed — " + result.subdomainCount() + " subdomains, " + result.aliveCount() + " alive");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("❌ Hata: " + t.getMessage()));
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

    private void refreshTableData(ReconResult result) {
        subdomainModel.setRowCount(0);
        List<SubdomainEntry> entries = result.getEntries();
        int i = 1;
        int totalIps = 0;
        int totalOpenPorts = 0;

        for (SubdomainEntry e : entries) {
            String ips = e.getIpsString();
            String ports = e.getPortsString();
            String httpCode = e.httpStatus() > 0 ? String.valueOf(e.httpStatus()) : "-";
            String titleServer = e.pageTitle() + (!"-".equals(e.serverHeader()) ? " [" + e.serverHeader() + "]" : "");
            String status = e.isAlive() ? "ALIVE" : (e.ips().isEmpty() ? "UNRESOLVED" : "RESOLVED");

            subdomainModel.addRow(new Object[]{
                    i++,
                    e.subdomain(),
                    ips,
                    ports,
                    httpCode,
                    titleServer,
                    status
            });

            totalIps += e.ips().size();
            totalOpenPorts += e.openPorts().size();
        }

        summaryLabel.setText("Subdomain: " + entries.size() +
                " | Canlı Host: " + result.aliveCount() +
                " | Toplam IP: " + totalIps +
                " | Açık Port: " + totalOpenPorts);
    }

    private void onCancel() {
        reconModule.cancel();
        statusLabel.setText("Keşif iptal ediliyor...");
        scanState.info("burpinho [RECON]: Recon pipeline cancelled by user");
    }

    private void onClear() {
        subdomainModel.setRowCount(0);
        outputArea.setText("");
        statusLabel.setText("Hazır");
        summaryLabel.setText("Subdomain: 0 | Canlı Host: 0 | Toplam IP: 0 | Açık Port: 0");
    }

    private void onExportCsv() {
        if (subdomainModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "Dışa aktarılacak veri yok!", "CSV Dışa Aktar", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("recon_results_" + System.currentTimeMillis() + ".csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,Subdomain,IPs,OpenPorts,HTTPCode,TitleServer,Status\n");
                for (int r = 0; r < subdomainModel.getRowCount(); r++) {
                    StringBuilder row = new StringBuilder();
                    for (int c = 0; c < subdomainModel.getColumnCount(); c++) {
                        String cell = String.valueOf(subdomainModel.getValueAt(r, c)).replace("\"", "\"\"");
                        row.append("\"").append(cell).append("\"");
                        if (c < subdomainModel.getColumnCount() - 1) row.append(",");
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
        int row = subdomainTable.getSelectedRow();
        if (row >= 0) {
            Object val = subdomainTable.getValueAt(row, col);
            if (val != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(val.toString()), null);
            }
        }
    }

    public void setTarget(String target) {
        targetField.setText(target);
    }

    public ReconResult getLastResult() {
        return lastResult;
    }
}
