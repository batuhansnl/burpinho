package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.sn1persecurity.silentchain.bapp.modules.jwt.JwtAttackEngine;
import com.sn1persecurity.silentchain.bapp.modules.jwt.JwtBruteForcer;
import com.sn1persecurity.silentchain.bapp.modules.jwt.JwtToken;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Advanced JWT Attack Panel — 4-section split-pane layout:
 *   Section 1: Token Input & Real-Time Decode
 *   Section 2: Attack Configuration & Brute-Force Settings
 *   Section 3: Attack Results Table (with Send to Repeater)
 *   Section 4: Live Attack Audit Log
 */
public class JwtPanel extends JPanel {

    /**
     * Internal container storing full untruncated attack results.
     */
    public record AttackResultItem(
            int id,
            String severity,
            String attackName,
            String fullModifiedToken,
            String status,
            String details
    ) {}

    private final MontoyaApi api;
    private final ThreadPool threadPool;
    private final ScanState scanState;
    private volatile boolean cancelled = false;

    // HTTP context from Burp
    private HttpRequest originalHttpRequest = null;
    private String originalRawToken = null;
    private final List<AttackResultItem> attackResultsList = Collections.synchronizedList(new ArrayList<>());

    // Token input
    private final JTextArea tokenInputArea = new JTextArea(3, 50);

    // Decoded view
    private final JTextArea headerArea = new JTextArea(6, 20);
    private final JTextArea payloadArea = new JTextArea(6, 20);
    private final JTextArea signatureInfoArea = new JTextArea(4, 20);

    // Attack selection checkboxes
    private final JCheckBox chkAlgNone = new JCheckBox("alg:none Bypass", true);
    private final JCheckBox chkBruteForce = new JCheckBox("HMAC Brute-Force", true);
    private final JCheckBox chkRsHs = new JCheckBox("RS→HS Karışıklığı (Confusion)", true);
    private final JCheckBox chkKidInject = new JCheckBox("kid Enjeksiyonu", true);
    private final JCheckBox chkJkuX5u = new JCheckBox("jku/x5u Sahteciliği (Spoofing)", true);
    private final JCheckBox chkJwkInject = new JCheckBox("jwk Kendi Kendine İmzalama (Self-Sign)", true);
    private final JCheckBox chkClaimTamper = new JCheckBox("Claim Değiştirme (Tampering)", true);
    private final JCheckBox chkExpiry = new JCheckBox("Süre Değiştirme (Expiry)", true);
    private final JCheckBox chkNullSig = new JCheckBox("Null İmza (Null Signature)", true);
    private final JCheckBox chkCrossService = new JCheckBox("Servisler Arası İletim (Relay)", true);
    private final JCheckBox chkNestedJwt = new JCheckBox("İç İçe JWT Analizi (Nested)", true);

    // Brute-force config
    private final JComboBox<String> wordlistCombo = new JComboBox<>(new String[]{
            "Dahili En Çok Kullanılan 500 Secret",
            "Dahili + Özel Dosya",
            "Sadece Özel Dosya"
    });
    private final JTextField customWordlistPath = new JTextField(20);
    private final JButton browseBtn = new JButton("Gözat...");
    private final JSpinner threadsSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 100, 5));

    // Action buttons
    private final JButton decodeBtn = new JButton("🔍 Token'ı Çöz (Decode)");
    private final JButton attackBtn = new JButton("🚀 Saldırıyı Başlat");
    private final JButton cancelBtn = new JButton("⏹ İptal Et");
    private final JButton clearBtn = new JButton("🗑 Hepsini Temizle");
    private final JButton exportBtn = new JButton("📤 CSV Dışa Aktar");
    private final JLabel statusLabel = new JLabel("Hazır — Başlamak için bir JWT token'ı yapıştırın");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel summaryLabel = new JLabel("Saldırılar: 0 | Bulgular: 0 | Denenen BF Anahtarları: 0");

    // Results table
    private final DefaultTableModel resultsModel;
    private final JTable resultsTable;

    // Live log
    private final JTextArea logArea;

    // State
    private JwtToken currentToken = null;
    private JwtBruteForcer activeBruteForcer = null;

    public JwtPanel(MontoyaApi api, ThreadPool threadPool, ScanState scanState) {
        this.api = api;
        this.threadPool = threadPool;
        this.scanState = scanState;

        setLayout(new BorderLayout(0, 4));
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        // ========== SECTION 1: Token Input & Decode ==========
        JPanel topSection = new JPanel(new BorderLayout(6, 4));
        topSection.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(88, 166, 255), 1),
                "🔐 JWT Token Girişi & Çözümleme (Decode)",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 12),
                new Color(88, 166, 255)));

        // Input row
        JPanel inputRow = new JPanel(new BorderLayout(6, 0));
        tokenInputArea.setToolTipText("Bir JWT token'ı (örn: eyJhbGciOi...) veya Bearer token içeren bir HTTP isteği yapıştırın");
        tokenInputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        tokenInputArea.setLineWrap(true);
        tokenInputArea.setWrapStyleWord(true);
        inputRow.add(new JScrollPane(tokenInputArea), BorderLayout.CENTER);

        JPanel inputBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        decodeBtn.setBackground(Theme.ACCENT_BLUE);
        decodeBtn.setForeground(Color.WHITE);
        decodeBtn.setOpaque(true);
        decodeBtn.setBorderPainted(false);
        decodeBtn.setFont(decodeBtn.getFont().deriveFont(Font.BOLD));
        decodeBtn.addActionListener(e -> onDecode());
        inputBtns.add(decodeBtn);

        JButton pasteBtn = new JButton("📋 Yapıştır");
        pasteBtn.addActionListener(e -> {
            try {
                String clipboard = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
                tokenInputArea.setText(clipboard);
                onDecode();
            } catch (Exception ex) {
                statusLabel.setText("⚠️ Pano boş veya erişilemiyor");
            }
        });
        inputBtns.add(pasteBtn);
        inputRow.add(inputBtns, BorderLayout.SOUTH);
        topSection.add(inputRow, BorderLayout.NORTH);

        // Decoded panels (Header | Payload | Signature Info)
        JPanel decodePanels = new JPanel(new GridLayout(1, 3, 6, 0));

        headerArea.setEditable(false);
        headerArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        headerArea.setBackground(new Color(22, 27, 34));
        headerArea.setForeground(new Color(126, 231, 135));
        JPanel headerPanel = wrapWithTitle("Header (JOSE)", headerArea, new Color(126, 231, 135));
        decodePanels.add(headerPanel);

        payloadArea.setEditable(false);
        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        payloadArea.setBackground(new Color(22, 27, 34));
        payloadArea.setForeground(new Color(210, 153, 255));
        JPanel payloadPanel = wrapWithTitle("Payload (Claims)", payloadArea, new Color(210, 153, 255));
        decodePanels.add(payloadPanel);

        signatureInfoArea.setEditable(false);
        signatureInfoArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        signatureInfoArea.setBackground(new Color(22, 27, 34));
        signatureInfoArea.setForeground(new Color(255, 166, 87));
        JPanel sigPanel = wrapWithTitle("İmza & Bilgi (Signature & Info)", signatureInfoArea, new Color(255, 166, 87));
        decodePanels.add(sigPanel);

        topSection.add(decodePanels, BorderLayout.CENTER);

        // ========== SECTION 2: Attack Configuration ==========
        JPanel configSection = new JPanel(new BorderLayout(6, 4));
        configSection.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(248, 81, 73), 1),
                "⚔️ Saldırı Yapılandırması",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 12),
                new Color(248, 81, 73)));

        // Attack checkboxes grid
        JPanel attackGrid = new JPanel(new GridLayout(3, 4, 4, 2));
        attackGrid.add(chkAlgNone);
        attackGrid.add(chkBruteForce);
        attackGrid.add(chkRsHs);
        attackGrid.add(chkKidInject);
        attackGrid.add(chkJkuX5u);
        attackGrid.add(chkJwkInject);
        attackGrid.add(chkClaimTamper);
        attackGrid.add(chkExpiry);
        attackGrid.add(chkNullSig);
        attackGrid.add(chkCrossService);
        attackGrid.add(chkNestedJwt);

        JButton selectAllBtn = new JButton("Tümünü Seç");
        selectAllBtn.addActionListener(e -> setAllAttacks(true));
        JButton deselectAllBtn = new JButton("Tümünü Kaldır");
        deselectAllBtn.addActionListener(e -> setAllAttacks(false));
        JPanel selBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        selBtns.add(selectAllBtn);
        selBtns.add(deselectAllBtn);
        attackGrid.add(selBtns);

        configSection.add(attackGrid, BorderLayout.NORTH);

        // Brute-force row
        JPanel bfRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        bfRow.add(new JLabel("Wordlist:"));
        bfRow.add(wordlistCombo);
        customWordlistPath.setEnabled(false);
        bfRow.add(customWordlistPath);
        browseBtn.setEnabled(false);
        browseBtn.addActionListener(e -> onBrowseWordlist());
        bfRow.add(browseBtn);
        bfRow.add(Box.createHorizontalStrut(12));
        bfRow.add(new JLabel("BF Threads:"));
        bfRow.add(threadsSpinner);

        wordlistCombo.addActionListener(e -> {
            boolean custom = wordlistCombo.getSelectedIndex() > 0;
            customWordlistPath.setEnabled(custom);
            browseBtn.setEnabled(custom);
        });

        configSection.add(bfRow, BorderLayout.CENTER);

        // Action buttons row
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        attackBtn.setBackground(new Color(248, 81, 73));
        attackBtn.setForeground(Color.WHITE);
        attackBtn.setOpaque(true);
        attackBtn.setBorderPainted(false);
        attackBtn.setFont(attackBtn.getFont().deriveFont(Font.BOLD, 13f));
        attackBtn.addActionListener(e -> onLaunchAttack());
        actionRow.add(attackBtn);

        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> onCancel());
        actionRow.add(cancelBtn);

        clearBtn.addActionListener(e -> onClear());
        actionRow.add(clearBtn);

        exportBtn.addActionListener(e -> onExportCsv());
        actionRow.add(exportBtn);

        actionRow.add(Box.createHorizontalStrut(12));
        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);
        progressBar.setPreferredSize(new Dimension(200, 18));
        actionRow.add(progressBar);
        actionRow.add(statusLabel);

        configSection.add(actionRow, BorderLayout.SOUTH);

        // ========== Combine top sections ==========
        JPanel topCombined = new JPanel();
        topCombined.setLayout(new BoxLayout(topCombined, BoxLayout.Y_AXIS));
        topCombined.add(topSection);
        topCombined.add(configSection);

        add(topCombined, BorderLayout.NORTH);

        // ========== SECTION 3: Results Table ==========
        String[] columnNames = {"#", "Severity", "Saldırı Türü", "Değiştirilmiş Token", "Durum", "Detaylar"};
        resultsModel = new DefaultTableModel(columnNames, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        resultsTable = new JTable(resultsModel);
        resultsTable.setRowSorter(new TableRowSorter<>(resultsModel));

        resultsTable.getColumnModel().getColumn(0).setMaxWidth(45);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(1).setMaxWidth(100);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(250);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(100);
        resultsTable.getColumnModel().getColumn(4).setMaxWidth(130);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(350);

        // Severity color renderer
        resultsTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, sel, focus, row, col);
                if (!sel && value != null) {
                    String sev = value.toString();
                    c.setForeground(switch (sev) {
                        case "CRITICAL" -> new Color(248, 81, 73);
                        case "HIGH" -> new Color(255, 123, 42);
                        case "MEDIUM" -> new Color(255, 200, 55);
                        case "LOW" -> new Color(88, 166, 255);
                        default -> new Color(139, 148, 158);
                    });
                    setFont(getFont().deriveFont(Font.BOLD));
                }
                return c;
            }
        });

        // Status color renderer
        resultsTable.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, sel, focus, row, col);
                if (!sel && value != null) {
                    String status = value.toString();
                    if (status.contains("BYPASS") || status.contains("CRACKED") || status.contains("SELF-SIGNED"))
                        c.setForeground(new Color(248, 81, 73));
                    else if (status.contains("INJECTED") || status.contains("SPOOFED") || status.contains("TAMPERED"))
                        c.setForeground(new Color(255, 166, 87));
                    else if (status.contains("TEST") || status.contains("CONCEPT") || status.contains("RELAY"))
                        c.setForeground(new Color(88, 166, 255));
                    else
                        c.setForeground(new Color(139, 148, 158));
                    setFont(getFont().deriveFont(Font.BOLD));
                }
                return c;
            }
        });

        // Context menu on results table
        JPopupMenu popup = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem("🔁 Burp Repeater'a Gönder");
        sendToRepeater.setFont(sendToRepeater.getFont().deriveFont(Font.BOLD));
        sendToRepeater.addActionListener(e -> onSendToRepeater());

        JMenuItem inspectItem = new JMenuItem("🔍 Panellerde İncele / Çözümle");
        inspectItem.addActionListener(e -> onInspectSelectedResult());

        JMenuItem copyToken = new JMenuItem("📋 Tam Değiştirilmiş Token'ı Kopyala");
        copyToken.addActionListener(e -> onCopyFullToken());

        JMenuItem copyDetails = new JMenuItem("📋 Saldırı Detaylarını Kopyala");
        copyDetails.addActionListener(e -> copyCell(5));

        JMenuItem copyCurl = new JMenuItem("💻 cURL Komutu Olarak Kopyala");
        copyCurl.addActionListener(e -> onCopyCurl());

        popup.add(sendToRepeater);
        popup.add(inspectItem);
        popup.addSeparator();
        popup.add(copyToken);
        popup.add(copyDetails);
        popup.add(copyCurl);
        resultsTable.setComponentPopupMenu(popup);

        // Double click row -> inspect token in decoder
        resultsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    onInspectSelectedResult();
                }
            }
        });

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(255, 200, 55), 1),
                "🎯 Saldırı Sonuçları",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 12),
                new Color(255, 200, 55)));
        tablePanel.add(new JScrollPane(resultsTable), BorderLayout.CENTER);

        // ========== SECTION 4: Live Attack Log ==========
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        logArea.setBackground(new Color(13, 17, 23));
        logArea.setForeground(new Color(201, 209, 217));

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(139, 148, 158), 1),
                "📜 Canlı Saldırı Denetim Günlüğü",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 12),
                new Color(139, 148, 158)));
        logPanel.add(new JScrollPane(logArea), BorderLayout.CENTER);

        // Split: Results | Log
        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, logPanel);
        centerSplit.setResizeWeight(0.55);
        centerSplit.setDividerLocation(260);

        add(centerSplit, BorderLayout.CENTER);

        // ========== Bottom Summary Bar ==========
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 3));
        bottomPanel.setBorder(BorderFactory.createEtchedBorder());
        bottomPanel.add(summaryLabel);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    // =====================================================================
    //  ACTIONS
    // =====================================================================

    private void onDecode() {
        String raw = tokenInputArea.getText().trim();
        if (raw.isEmpty()) {
            statusLabel.setText("⚠️ Önce bir JWT token'ı yapıştırın!");
            return;
        }

        // Try to extract JWT from raw HTTP request or plain text
        String extracted = JwtToken.extractFromRequest(raw);
        if (extracted == null) {
            // Maybe it's a direct token
            if (JwtToken.isJwt(raw)) {
                extracted = raw;
            } else {
                statusLabel.setText("❌ Girdide geçerli bir JWT bulunamadı.");
                return;
            }
        }

        try {
            currentToken = JwtToken.parse(extracted);

            // Update decoded panels
            headerArea.setText(currentToken.headerJson());
            payloadArea.setText(currentToken.payloadJson());

            // Signature info
            StringBuilder sigInfo = new StringBuilder();
            Map<String, String> summary = currentToken.summary();
            for (Map.Entry<String, String> entry : summary.entrySet()) {
                sigInfo.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
            signatureInfoArea.setText(sigInfo.toString());

            statusLabel.setText("✅ JWT başarıyla çözümlendi — " + currentToken.algorithm() + " | " +
                    (currentToken.isExpired() ? "⚠️ SÜRESİ DOLMUŞ (EXPIRED)" : "Geçerli"));

            log("[JWT-DECODE] Token ayrıştırıldı: alg=" + currentToken.algorithm() +
                    ", sub=" + currentToken.subject() +
                    ", exp=" + (currentToken.expiration() > 0 ? new java.util.Date(currentToken.expiration() * 1000L) : "N/A") +
                    ", expired=" + currentToken.isExpired());

        } catch (Exception e) {
            statusLabel.setText("❌ Ayrıştırma hatası: " + e.getMessage());
            log("[JWT-DECODE] ❌ Ayrıştırma başarısız: " + e.getMessage());
            currentToken = null;
        }
    }

    private void onLaunchAttack() {
        if (currentToken == null) {
            onDecode();
            if (currentToken == null) {
                statusLabel.setText("⚠️ Önce geçerli bir JWT çözümleyin!");
                return;
            }
        }

        cancelled = false;
        attackBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("⚔️ JWT saldırıları başlatılıyor...");
        resultsModel.setRowCount(0);
        attackResultsList.clear();

        scanState.info("burpinho [JWT]: Starting JWT attack suite on " + currentToken.algorithm() + " token");

        threadPool.submit(() -> {
            try {
                runAttacks();
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("❌ Saldırı hatası: " + t.getMessage()));
                log("[JWT-ATTACK] ❌ Fatal error: " + t.getMessage());
            } finally {
                SwingUtilities.invokeLater(() -> {
                    attackBtn.setEnabled(true);
                    cancelBtn.setEnabled(false);
                    progressBar.setVisible(false);
                });
            }
        });
    }

    private void runAttacks() {
        JwtAttackEngine engine = new JwtAttackEngine();
        engine.setLogCallback(this::log);

        // Build config from checkboxes
        JwtAttackEngine.AttackConfig config = new JwtAttackEngine.AttackConfig();
        config.algNone = chkAlgNone.isSelected();
        config.hmacBruteForce = chkBruteForce.isSelected();
        config.rsHsConfusion = chkRsHs.isSelected();
        config.kidInjection = chkKidInject.isSelected();
        config.jkuX5uSpoofing = chkJkuX5u.isSelected();
        config.jwkInjection = chkJwkInject.isSelected();
        config.claimTampering = chkClaimTamper.isSelected();
        config.expiryManip = chkExpiry.isSelected();
        config.nullSignature = chkNullSig.isSelected();
        config.crossServiceRelay = chkCrossService.isSelected();
        config.nestedJwt = chkNestedJwt.isSelected();

        // Run non-brute-force attacks
        List<JwtAttackEngine.AttackResult> results = engine.runAllAttacks(currentToken, config);

        int attackCount = results.size();
        int criticalCount = 0;

        for (JwtAttackEngine.AttackResult r : results) {
            if (cancelled) break;
            if ("CRITICAL".equals(r.severity()) || "HIGH".equals(r.severity())) criticalCount++;

            final int id = attackResultsList.size() + 1;
            AttackResultItem item = new AttackResultItem(
                    id, r.severity(), r.attackName(), r.modifiedToken(), r.status(), r.details()
            );
            attackResultsList.add(item);

            final String truncatedToken = r.modifiedToken().length() > 60
                    ? r.modifiedToken().substring(0, 60) + "..."
                    : r.modifiedToken();

            SwingUtilities.invokeLater(() -> {
                resultsModel.addRow(new Object[]{
                        id, r.severity(), r.attackName(), truncatedToken, r.status(), r.details()
                });
            });
        }

        // Run brute-force if selected
        int bfKeysCount = 0;
        if (config.hmacBruteForce && !cancelled && currentToken.algorithm().startsWith("HS")) {
            log("[JWT-BRUTE] ═══════════════════════════════════════════════");
            log("[JWT-BRUTE] HMAC Secret Brute-Force başlatılıyor...");
            log("[JWT-BRUTE] ═══════════════════════════════════════════════");

            int threads = (int) threadsSpinner.getValue();
            JwtBruteForcer bruteForcer = new JwtBruteForcer(currentToken);
            activeBruteForcer = bruteForcer;
            bruteForcer.setLogCallback(this::log);
            bruteForcer.setProgressCallback(progress -> {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setIndeterminate(false);
                    progressBar.setMaximum(progress.total());
                    progressBar.setValue(progress.current());
                    statusLabel.setText(String.format("🔑 BF: %,d/%,d (%.0f anahtar/sn)",
                            progress.current(), progress.total(), progress.keysPerSec()));
                });
            });

            JwtBruteForcer.BruteForceResult bfResult;
            int wordlistIdx = wordlistCombo.getSelectedIndex();

            if (wordlistIdx == 0) {
                bfResult = bruteForcer.bruteForceBuiltIn(threads);
            } else {
                String filePath = customWordlistPath.getText().trim();
                File wordlistFile = filePath.isEmpty() ? null : new File(filePath);
                if (wordlistIdx == 2 && (wordlistFile == null || !wordlistFile.exists())) {
                    log("[JWT-BRUTE] ⚠️ Özel wordlist dosyası bulunamadı, dahili listeye geçiliyor.");
                    bfResult = bruteForcer.bruteForceBuiltIn(threads);
                } else {
                    bfResult = bruteForcer.bruteForceFromFile(wordlistFile, threads);
                }
            }

            bfKeysCount = bfResult.totalAttempts();

            if (bfResult.cracked()) {
                attackCount++;
                criticalCount++;
                String crackedSecret = bfResult.secret();
                String resignedToken = currentToken.buildSignedHmac(crackedSecret, currentToken.algorithm());

                final int id = attackResultsList.size() + 1;
                AttackResultItem item = new AttackResultItem(
                        id, "CRITICAL",
                        "HMAC BF (secret=\"" + crackedSecret + "\")",
                        resignedToken,
                        "🔥 CRACKED",
                        "Secret kırıldı: \"" + crackedSecret + "\" — " + bfResult.summary()
                );
                attackResultsList.add(item);

                SwingUtilities.invokeLater(() -> {
                    resultsModel.addRow(new Object[]{
                            id, "CRITICAL",
                            "HMAC BF (secret=\"" + crackedSecret + "\")",
                            resignedToken.length() > 60 ? resignedToken.substring(0, 60) + "..." : resignedToken,
                            "🔥 CRACKED",
                            "Secret kırıldı: \"" + crackedSecret + "\" — " + bfResult.summary()
                    });
                });
            } else {
                final int id = attackResultsList.size() + 1;
                AttackResultItem item = new AttackResultItem(
                        id, "INFO",
                        "HMAC Brute-Force",
                        "N/A",
                        "❌ NOT FOUND",
                        bfResult.summary()
                );
                attackResultsList.add(item);

                SwingUtilities.invokeLater(() -> {
                    resultsModel.addRow(new Object[]{
                            id, "INFO",
                            "HMAC Brute-Force",
                            "N/A",
                            "❌ NOT FOUND",
                            bfResult.summary()
                    });
                });
            }

            activeBruteForcer = null;
        }

        final int fc = criticalCount;
        final int ac = attackCount;
        final int bfk = bfKeysCount;
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("✅ JWT saldırı paketi tamamlandı — " + fc + " critical/high bulgu. Repeater'a göndermek için bir satıra sağ tıklayın.");
            summaryLabel.setText("Saldırılar: " + ac + " | Critical/High: " + fc + " | Denenen BF Anahtarları: " + bfk);
            scanState.info("burpinho [JWT]: Attack suite complete — " + ac + " results, " + fc + " critical/high.");
        });
    }

    private void onCancel() {
        cancelled = true;
        if (activeBruteForcer != null) {
            activeBruteForcer.cancel();
        }
        statusLabel.setText("⏹ Saldırı iptal edildi.");
        scanState.info("burpinho [JWT]: Attack cancelled by user.");
    }

    private void onClear() {
        resultsModel.setRowCount(0);
        attackResultsList.clear();
        originalHttpRequest = null;
        originalRawToken = null;
        logArea.setText("");
        headerArea.setText("");
        payloadArea.setText("");
        signatureInfoArea.setText("");
        tokenInputArea.setText("");
        currentToken = null;
        statusLabel.setText("Hazır — Başlamak için bir JWT token'ı yapıştırın");
        summaryLabel.setText("Saldırılar: 0 | Bulgular: 0 | Denenen BF Anahtarları: 0");
    }

    private void onBrowseWordlist() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("JWT Secret Wordlist Dosyası Seçin");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            customWordlistPath.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void onExportCsv() {
        if (resultsModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "Dışa aktarılacak JWT saldırı sonucu yok!", "CSV Dışa Aktar", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("jwt_attack_results_" + System.currentTimeMillis() + ".csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,Severity,AttackType,ModifiedToken,Status,Details\n");
                for (int r = 0; r < resultsModel.getRowCount(); r++) {
                    StringBuilder row = new StringBuilder();
                    for (int c = 0; c < resultsModel.getColumnCount(); c++) {
                        String cell = String.valueOf(resultsModel.getValueAt(r, c)).replace("\"", "\"\"");
                        row.append("\"").append(cell).append("\"");
                        if (c < resultsModel.getColumnCount() - 1) row.append(",");
                    }
                    fw.write(row + "\n");
                }
                JOptionPane.showMessageDialog(this, "Başarıyla dışa aktarıldı: " + f.getAbsolutePath(), "CSV Dışa Aktar", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Dışa aktarma başarısız: " + ex.getMessage(), "Hata", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // =====================================================================
    //  REPEATER & RESULT ACTIONS
    // =====================================================================

    /**
     * Send selected attack payload as a full HTTP request directly to Burp Repeater.
     */
    private void onSendToRepeater() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) {
            statusLabel.setText("⚠️ Lütfen önce bir saldırı sonuç satırı seçin.");
            return;
        }

        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
        AttackResultItem item = null;
        synchronized (attackResultsList) {
            if (modelRow >= 0 && modelRow < attackResultsList.size()) {
                item = attackResultsList.get(modelRow);
            }
        }

        if (item == null || item.fullModifiedToken() == null || item.fullModifiedToken().isEmpty() || "N/A".equals(item.fullModifiedToken())) {
            statusLabel.setText("⚠️ Seçilen satırda saldırı payload token'ı bulunmuyor.");
            return;
        }

        String token = item.fullModifiedToken();
        String attackName = item.attackName();
        String tabTitle = "JWT: " + (attackName.length() > 22 ? attackName.substring(0, 22) + "..." : attackName);

        HttpRequest requestToSend = null;

        try {
            if (originalHttpRequest != null) {
                // If we have the original Burp request, replace the old JWT with modified attack JWT
                String rawReq = originalHttpRequest.toString();
                if (originalRawToken != null && !originalRawToken.isEmpty() && rawReq.contains(originalRawToken)) {
                    String modifiedRaw = rawReq.replace(originalRawToken, token);
                    if (originalHttpRequest.httpService() != null) {
                        requestToSend = HttpRequest.httpRequest(originalHttpRequest.httpService(), modifiedRaw);
                    } else {
                        requestToSend = HttpRequest.httpRequest(modifiedRaw);
                    }
                } else if (originalHttpRequest.hasHeader("Authorization")) {
                    requestToSend = originalHttpRequest.withUpdatedHeader("Authorization", "Bearer " + token);
                } else {
                    requestToSend = originalHttpRequest.withAddedHeader("Authorization", "Bearer " + token);
                }
            } else {
                // Check if user pasted a raw HTTP request in token input area
                String input = tokenInputArea.getText().trim();
                if (input.startsWith("GET ") || input.startsWith("POST ") || input.startsWith("PUT ") ||
                    input.startsWith("DELETE ") || input.startsWith("PATCH ") || input.startsWith("HEAD ") ||
                    input.startsWith("OPTIONS ")) {

                    String tokenToReplace = JwtToken.extractFromRequest(input);
                    String modifiedReq = (tokenToReplace != null && !tokenToReplace.isEmpty() && input.contains(tokenToReplace))
                            ? input.replace(tokenToReplace, token)
                            : input;
                    requestToSend = HttpRequest.httpRequest(modifiedReq);
                } else {
                    // Build a standard template HTTP request with target host
                    String host = "target.local";
                    if (currentToken != null && currentToken.issuer() != null && !currentToken.issuer().isEmpty()) {
                        try {
                            String iss = currentToken.issuer();
                            if (iss.startsWith("http://") || iss.startsWith("https://")) {
                                host = new java.net.URI(iss).getHost();
                            } else {
                                host = iss.replaceAll("[^a-zA-Z0-9.-]", "");
                            }
                        } catch (Exception ignored) {}
                    }
                    if (host == null || host.isEmpty()) host = "target.local";

                    String template = "GET /api/v1/user HTTP/1.1\r\n" +
                            "Host: " + host + "\r\n" +
                            "Authorization: Bearer " + token + "\r\n" +
                            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) burpinho/4.0.1\r\n" +
                            "Accept: application/json, text/plain, */*\r\n" +
                            "Connection: close\r\n\r\n";
                    requestToSend = HttpRequest.httpRequest(template);
                }
            }

            if (api != null && api.repeater() != null && requestToSend != null) {
                api.repeater().sendToRepeater(requestToSend, tabTitle);
                statusLabel.setText("🔁 [" + attackName + "] Burp Repeater sekmesine gönderildi: '" + tabTitle + "'");
                log("[JWT-REPEATER] 🔁 Başarıyla Burp Repeater sekmesine gönderildi: " + tabTitle +
                        " | Payload: " + (token.length() > 60 ? token.substring(0, 60) + "..." : token));
                scanState.info("burpinho [JWT]: Sent attack payload '" + attackName + "' to Burp Repeater.");
            } else {
                copyToClipboard(token);
                statusLabel.setText("⚠️ Repeater API kullanılamıyor — token panoya kopyalandı.");
            }
        } catch (Exception ex) {
            log("[JWT-REPEATER] ❌ Repeater'a gönderilemedi: " + ex.getMessage());
            statusLabel.setText("❌ Repeater'a gönderirken hata: " + ex.getMessage());
        }
    }

    /**
     * Inspect selected attack result directly in the Header, Payload, and Signature decoder panels.
     */
    private void onInspectSelectedResult() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) return;

        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
        AttackResultItem item = null;
        synchronized (attackResultsList) {
            if (modelRow >= 0 && modelRow < attackResultsList.size()) {
                item = attackResultsList.get(modelRow);
            }
        }

        if (item == null || item.fullModifiedToken() == null || "N/A".equals(item.fullModifiedToken())) {
            return;
        }

        String token = item.fullModifiedToken();
        try {
            JwtToken parsed = JwtToken.parse(token);
            headerArea.setText(parsed.headerJson());
            payloadArea.setText(parsed.payloadJson());

            StringBuilder sigInfo = new StringBuilder();
            sigInfo.append("=== SALDIRI PAYLOAD'I İNCELENİYOR ===\n");
            sigInfo.append("Saldırı: ").append(item.attackName()).append("\n");
            sigInfo.append("Severity: ").append(item.severity()).append("\n");
            sigInfo.append("Durum: ").append(item.status()).append("\n");
            sigInfo.append("Algoritma: ").append(parsed.algorithm()).append("\n");
            sigInfo.append("İmza Boyutu: ").append(parsed.signatureBytes().length).append(" bayt\n");
            sigInfo.append("Detaylar: ").append(item.details()).append("\n");
            signatureInfoArea.setText(sigInfo.toString());

            statusLabel.setText("🔍 Payload inceleniyor: " + item.attackName() + " (" + item.severity() + ")");
            log("[JWT-INSPECT] 🔍 Saldırı token'ı inceleniyor: '" + item.attackName() + "' (alg: " + parsed.algorithm() + ")");
        } catch (Exception ex) {
            headerArea.setText("Token: " + token);
            payloadArea.setText("Detaylar: " + item.details());
            signatureInfoArea.setText("Durum: " + item.status());
            statusLabel.setText("🔍 Payload gösteriliyor: " + item.attackName());
        }
    }

    /**
     * Copy full untruncated modified token to clipboard.
     */
    private void onCopyFullToken() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) return;

        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
        AttackResultItem item = null;
        synchronized (attackResultsList) {
            if (modelRow >= 0 && modelRow < attackResultsList.size()) {
                item = attackResultsList.get(modelRow);
            }
        }

        if (item != null && item.fullModifiedToken() != null) {
            copyToClipboard(item.fullModifiedToken());
            statusLabel.setText("📋 [" + item.attackName() + "] için tam değiştirilmiş token panoya kopyalandı!");
        }
    }

    /**
     * Copy as a ready-to-run cURL command.
     */
    private void onCopyCurl() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) return;

        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
        AttackResultItem item = null;
        synchronized (attackResultsList) {
            if (modelRow >= 0 && modelRow < attackResultsList.size()) {
                item = attackResultsList.get(modelRow);
            }
        }

        if (item == null || item.fullModifiedToken() == null || "N/A".equals(item.fullModifiedToken())) {
            return;
        }

        String token = item.fullModifiedToken();
        String url = "https://target.local/api/user";
        if (originalHttpRequest != null && originalHttpRequest.url() != null) {
            url = originalHttpRequest.url();
        }
        String curl = "curl -k -i -X GET '" + url + "' \\\n  -H 'Authorization: Bearer " + token + "'";
        copyToClipboard(curl);
        statusLabel.setText("💻 [" + item.attackName() + "] için cURL komutu panoya kopyalandı!");
    }

    // =====================================================================
    //  PUBLIC API (for context menu integration)
    // =====================================================================

    /**
     * Set both the original Burp HttpRequest and the extracted JWT token.
     */
    public void setRequestAndToken(HttpRequest request, String jwt) {
        this.originalHttpRequest = request;
        this.originalRawToken = jwt;
        tokenInputArea.setText(jwt);
        onDecode();
        String urlStr = (request != null && request.url() != null) ? request.url() : "HTTP Request";
        statusLabel.setText("✅ Burp isteğinden JWT yüklendi: " + urlStr);
        log("[JWT-IMPORT] 📥 URL için istek alındı: " + urlStr + " token alg=" +
                (currentToken != null ? currentToken.algorithm() : "unknown"));
    }

    /**
     * Set token from external source (e.g., context menu / text).
     */
    public void setToken(String rawTokenOrRequest) {
        this.originalHttpRequest = null;
        this.originalRawToken = rawTokenOrRequest;
        tokenInputArea.setText(rawTokenOrRequest);
        onDecode();
    }

    /**
     * Set the full HTTP request and auto-extract JWT.
     */
    public void setHttpRequest(String httpRequest) {
        try {
            this.originalHttpRequest = HttpRequest.httpRequest(httpRequest);
        } catch (Exception ignored) {}

        String jwt = JwtToken.extractFromRequest(httpRequest);
        if (jwt != null) {
            this.originalRawToken = jwt;
            tokenInputArea.setText(jwt);
            onDecode();
        } else {
            tokenInputArea.setText(httpRequest);
            statusLabel.setText("⚠️ İstekte JWT tespit edilemedi — token'ı doğrudan yapıştırmayı deneyin.");
        }
    }

    // =====================================================================
    //  HELPERS
    // =====================================================================

    private void log(String msg) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(msg + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("JWT: " + msg);
        }
    }

    private void setAllAttacks(boolean selected) {
        chkAlgNone.setSelected(selected);
        chkBruteForce.setSelected(selected);
        chkRsHs.setSelected(selected);
        chkKidInject.setSelected(selected);
        chkJkuX5u.setSelected(selected);
        chkJwkInject.setSelected(selected);
        chkClaimTamper.setSelected(selected);
        chkExpiry.setSelected(selected);
        chkNullSig.setSelected(selected);
        chkCrossService.setSelected(selected);
        chkNestedJwt.setSelected(selected);
    }

    private void copyCell(int col) {
        int row = resultsTable.getSelectedRow();
        if (row >= 0) {
            Object val = resultsTable.getValueAt(row, col);
            if (val != null) copyToClipboard(val.toString());
        }
    }

    private void copyToClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    private JPanel wrapWithTitle(String title, JTextArea area, Color borderColor) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(borderColor, 1),
                title,
                javax.swing.border.TitledBorder.CENTER,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 11),
                borderColor));
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        return panel;
    }
}
