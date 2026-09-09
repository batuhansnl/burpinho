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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dedicated Path & Endpoint Fuzzer Panel.
 * Supports URL /FUZZ substitution, wordlist presets, status filters, and live HTTP probing.
 */
public class FuzzerPanel extends JPanel {

    private final MontoyaApi api;
    private final ThreadPool threadPool;
    private final ScanState scanState;
    private volatile boolean cancelled = false;

    private final JTextField urlField = new JTextField(24);
    private final JComboBox<String> wordlistCombo = new JComboBox<>(new String[]{
            "Yaygın Web Yolları (50+)",
            "Admin, Giriş & Portallar (50+)",
            "API & Mikroservis Endpoint'leri (50+)",
            "Hassas Dosyalar & Yedekler (40+)",
            "Özel Wordlist..."
    });
    private final JTextField statusFilterField = new JTextField("200, 201, 301, 302, 307, 401, 403, 500", 14);
    private final JSpinner threadsSpinner = new JSpinner(new SpinnerNumberModel(20, 1, 100, 5));
    private final JTextArea customWordlistArea = new JTextArea(3, 20);

    private final JButton startBtn = new JButton("Fuzzing Başlat");
    private final JButton cancelBtn = new JButton("İptal Et");
    private final JButton clearBtn = new JButton("Temizle");
    private final JButton exportBtn = new JButton("CSV Dışa Aktar");
    private final JLabel statusLabel = new JLabel("Hazır");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel summaryLabel = new JLabel("Keşfedilen Endpoint'ler: 0 | Gönderilen Toplam İstek: 0");

    private final DefaultTableModel pathsModel;
    private final JTable pathsTable;
    private final JTextArea logArea;

    public FuzzerPanel(MontoyaApi api, ThreadPool threadPool, ScanState scanState) {
        this.api = api;
        this.threadPool = threadPool;
        this.scanState = scanState;

        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top Config ----
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("Path & Endpoint Fuzzer Yapılandırması"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("Hedef URL (/FUZZ ile):"), gbc);
        gbc.gridx = 1;
        urlField.setToolTipText("örn: https://example.com/FUZZ veya https://example.com");
        configPanel.add(urlField, gbc);

        gbc.gridx = 2;
        configPanel.add(new JLabel("Wordlist Profili:"), gbc);
        gbc.gridx = 3;
        configPanel.add(wordlistCombo, gbc);

        // Row 1: Filters, Threads, Buttons
        gbc.gridx = 0; gbc.gridy = 1;
        configPanel.add(new JLabel("Eşleşen Status Kodları:"), gbc);
        gbc.gridx = 1;
        JPanel fPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        fPanel.add(statusFilterField);
        fPanel.add(new JLabel("Threads:"));
        fPanel.add(threadsSpinner);
        configPanel.add(fPanel, gbc);

        gbc.gridx = 2; gbc.gridwidth = 2;
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

        // ---- Center: Table & Live Log Split Pane ----
        String[] columnNames = {"#", "Fuzz Edilen URL", "HTTP Status", "Boyut", "Başlık / Yönlendirme", "Gecikme"};
        pathsModel = new DefaultTableModel(columnNames, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        pathsTable = new JTable(pathsModel);
        pathsTable.setRowSorter(new TableRowSorter<>(pathsModel));

        pathsTable.getColumnModel().getColumn(0).setMaxWidth(50);
        pathsTable.getColumnModel().getColumn(1).setPreferredWidth(260);
        pathsTable.getColumnModel().getColumn(2).setPreferredWidth(85);
        pathsTable.getColumnModel().getColumn(2).setMaxWidth(100);
        pathsTable.getColumnModel().getColumn(3).setPreferredWidth(85);
        pathsTable.getColumnModel().getColumn(3).setMaxWidth(100);
        pathsTable.getColumnModel().getColumn(4).setPreferredWidth(220);
        pathsTable.getColumnModel().getColumn(5).setPreferredWidth(80);

        // Status code color renderer
        pathsTable.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                String val = String.valueOf(value);
                if (!isSelected) {
                    if (val.startsWith("2")) {
                        c.setForeground(new Color(63, 185, 80));
                        setFont(getFont().deriveFont(Font.BOLD));
                    } else if (val.startsWith("3")) {
                        c.setForeground(new Color(88, 166, 255));
                    } else if (val.startsWith("4")) {
                        c.setForeground(new Color(240, 136, 62));
                    } else if (val.startsWith("5")) {
                        c.setForeground(new Color(248, 81, 73));
                    }
                }
                return c;
            }
        });

        // Popup Menu
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyUrl = new JMenuItem("Endpoint URL'sini Kopyala");
        copyUrl.addActionListener(e -> copySelectedCell(1));
        popupMenu.add(copyUrl);
        pathsTable.setComponentPopupMenu(popupMenu);

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setBackground(new Color(22, 27, 34));
        logArea.setForeground(new Color(201, 209, 217));

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder("Keşfedilen Web Endpoint'leri & Kaynaklar"));
        tablePanel.add(new JScrollPane(pathsTable), BorderLayout.CENTER);

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Fuzzing Canlı HTTP İstek Günlüğü"));
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
        String rawUrl = urlField.getText().trim();
        if (rawUrl.isEmpty()) {
            statusLabel.setText("⚠️ Bir hedef URL girin!");
            return;
        }

        if (!rawUrl.startsWith("http")) {
            rawUrl = "https://" + rawUrl;
        }

        final String baseUrl = rawUrl.contains("FUZZ") ? rawUrl : rawUrl.replaceAll("/+$", "") + "/FUZZ";
        List<String> words = getSelectedWordlist();
        List<Integer> allowedCodes = parseAllowedCodes(statusFilterField.getText());
        int threads = (int) threadsSpinner.getValue();

        cancelled = false;
        startBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("Endpoint'ler taranıyor (fuzzing)...");
        logArea.setText("");
        pathsModel.setRowCount(0);

        scanState.info("burpinho [FUZZER]: Starting fuzzing for " + baseUrl + " (" + words.size() + " payloads)");

        threadPool.submit(() -> {
            try {
                runFuzzing(baseUrl, words, allowedCodes, threads);
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("✅ Fuzzing tamamlandı.");
                    scanState.info("burpinho [FUZZER]: Fuzzing finished.");
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

    private void runFuzzing(String pattern, List<String> words, List<Integer> allowedCodes, int threads) {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        int[] stats = new int[]{0, 0}; // [sent, discovered]

        for (String word : words) {
            if (cancelled) break;
            final String cleanWord = word.startsWith("/") ? word.substring(1) : word;
            final String targetUrl = pattern.replace("FUZZ", cleanWord);

            pool.submit(() -> {
                if (cancelled) return;
                stats[0]++;
                long t0 = System.currentTimeMillis();

                try {
                    URL u = new URI(targetUrl).toURL();
                    HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                    conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) burpinho/4.0");
                    conn.setConnectTimeout(4000);
                    conn.setReadTimeout(4000);
                    conn.setInstanceFollowRedirects(false);

                    int code = conn.getResponseCode();
                    long latency = System.currentTimeMillis() - t0;
                    int length = conn.getContentLength();
                    String location = conn.getHeaderField("Location");
                    String title = "-";

                    try (BufferedReader br = new BufferedReader(new InputStreamReader(
                            code >= 400 ? conn.getErrorStream() : conn.getInputStream(), StandardCharsets.UTF_8))) {
                        StringBuilder body = new StringBuilder();
                        String line;
                        while ((line = br.readLine()) != null && body.length() < 10000) {
                            body.append(line);
                        }
                        Matcher m = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE).matcher(body);
                        if (m.find()) {
                            title = m.group(1).trim().replaceAll("\\s+", " ");
                        }
                    } catch (Throwable ignored) {}

                    log("[" + code + "] " + targetUrl + " (" + length + " bytes, " + latency + "ms)");

                    if (allowedCodes.contains(code)) {
                        stats[1]++;
                        String detail = (location != null ? "Yönlendirme -> " + location : title);
                        final String finalTitle = detail;
                        SwingUtilities.invokeLater(() -> {
                            int id = pathsModel.getRowCount() + 1;
                            pathsModel.addRow(new Object[]{
                                    id, targetUrl, code, length >= 0 ? length : "-", finalTitle, latency + "ms"
                            });
                            summaryLabel.setText("Keşfedilen Endpoint'ler: " + stats[1] + " | Gönderilen Toplam İstek: " + stats[0]);
                        });
                    }
                } catch (Throwable t) {
                    log("[!] " + targetUrl + " -> " + t.getMessage());
                }
            });
        }

        pool.shutdown();
        try {
            pool.awaitTermination(20, TimeUnit.MINUTES);
        } catch (InterruptedException ignored) {}

        SwingUtilities.invokeLater(() -> {
            summaryLabel.setText("Keşfedilen Endpoint'ler: " + stats[1] + " | Gönderilen Toplam İstek: " + stats[0]);
        });
    }

    private List<String> getSelectedWordlist() {
        int idx = wordlistCombo.getSelectedIndex();
        return switch (idx) {
            case 0 -> Arrays.asList(
                    "admin", "login", "dashboard", "api", "api/v1", "api/v2", "v1", "v2", "app", "portal",
                    "console", "manage", "manager", "wp-admin", "auth", "oauth", "sso", "user", "users",
                    "account", "accounts", "profile", "config", "setup", "install", "status", "health",
                    "metrics", "test", "dev", "staging", "beta", "internal", "private", "secret", "uploads",
                    "media", "static", "assets", "files", "download", "downloads", "backup", "backups",
                    "db", "data", "robots.txt", "sitemap.xml", ".well-known/security.txt", "swagger.json",
                    "openapi.json", "actuator/health", "phpinfo.php"
            );
            case 1 -> Arrays.asList(
                    "admin", "administrator", "admin/login", "admin/dashboard", "cpanel", "whm", "webmail",
                    "login", "signin", "auth", "authenticate", "portal", "console", "manager/html", "user/login",
                    "wp-login.php", "wp-admin", "ghost/admin", "typo3", "drupal/login", "joomla/administrator",
                    "oauth/authorize", "oauth/token", "saml/login", "sso/login", "idp", "keycloak", "cas/login"
            );
            case 2 -> Arrays.asList(
                    "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "v3", "graphql", "graphiql", "api/graphql",
                    "swagger.json", "swagger/v1/swagger.json", "openapi.json", "api-docs", "v2/api-docs", "v3/api-docs",
                    "swagger-ui.html", "swagger-ui/index.html", "docs", "api/users", "api/auth", "api/login",
                    "api/register", "api/token", "api/health", "api/status", "api/config", "api/ping"
            );
            case 3 -> Arrays.asList(
                    ".env", ".env.local", ".env.production", ".env.backup", ".git/HEAD", ".git/config",
                    ".svn/entries", "backup.sql", "dump.sql", "db.sql", "backup.zip", "backup.tar.gz",
                    "www.zip", "site.zip", ".DS_Store", "phpinfo.php", "info.php", "server-status", "elmah.axd",
                    "web.config", "crossdomain.xml", "clientaccesspolicy.xml", ".bash_history", "actuator/env"
            );
            default -> Arrays.asList("admin", "login", "api", "dashboard", "robots.txt");
        };
    }

    private List<Integer> parseAllowedCodes(String str) {
        List<Integer> list = new ArrayList<>();
        for (String t : str.split("[,;\\s]+")) {
            try {
                list.add(Integer.parseInt(t.trim()));
            } catch (NumberFormatException ignored) {}
        }
        return list.isEmpty() ? List.of(200, 301, 302, 401, 403) : list;
    }

    private void log(String msg) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(msg + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("FUZZER: " + msg);
        }
    }

    private void onCancel() {
        cancelled = true;
        statusLabel.setText("Fuzzer iptal ediliyor...");
        scanState.info("burpinho [FUZZER]: Cancelled by user");
    }

    private void onClear() {
        pathsModel.setRowCount(0);
        logArea.setText("");
        statusLabel.setText("Hazır");
        summaryLabel.setText("Keşfedilen Endpoint'ler: 0 | Gönderilen Toplam İstek: 0");
    }

    private void onExportCsv() {
        if (pathsModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "Dışa aktarılacak fuzzing sonucu yok!", "CSV Dışa Aktar", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("fuzzer_results_" + System.currentTimeMillis() + ".csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,EndpointURL,StatusCode,ContentLength,TitleLocation,Latency\n");
                for (int r = 0; r < pathsModel.getRowCount(); r++) {
                    StringBuilder row = new StringBuilder();
                    for (int c = 0; c < pathsModel.getColumnCount(); c++) {
                        String cell = String.valueOf(pathsModel.getValueAt(r, c)).replace("\"", "\"\"");
                        row.append("\"").append(cell).append("\"");
                        if (c < pathsModel.getColumnCount() - 1) row.append(",");
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
        int row = pathsTable.getSelectedRow();
        if (row >= 0) {
            Object val = pathsTable.getValueAt(row, col);
            if (val != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(val.toString()), null);
            }
        }
    }

    public void setTarget(String target) {
        urlField.setText(target);
    }
}
