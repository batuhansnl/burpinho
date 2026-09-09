package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

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
import java.util.List;
import java.util.Map;

/**
 * Advanced JWT Attack Panel — 4-section split-pane layout:
 *   Section 1: Token Input & Real-Time Decode
 *   Section 2: Attack Configuration & Brute-Force Settings
 *   Section 3: Attack Results Table
 *   Section 4: Live Attack Audit Log
 */
public class JwtPanel extends JPanel {

    private final MontoyaApi api;
    private final ThreadPool threadPool;
    private final ScanState scanState;
    private volatile boolean cancelled = false;

    // Token input
    private final JTextArea tokenInputArea = new JTextArea(3, 50);

    // Decoded view
    private final JTextArea headerArea = new JTextArea(6, 20);
    private final JTextArea payloadArea = new JTextArea(6, 20);
    private final JTextArea signatureInfoArea = new JTextArea(4, 20);

    // Attack selection checkboxes
    private final JCheckBox chkAlgNone = new JCheckBox("alg:none Bypass", true);
    private final JCheckBox chkBruteForce = new JCheckBox("HMAC Brute-Force", true);
    private final JCheckBox chkRsHs = new JCheckBox("RS→HS Confusion", true);
    private final JCheckBox chkKidInject = new JCheckBox("kid Injection", true);
    private final JCheckBox chkJkuX5u = new JCheckBox("jku/x5u Spoofing", true);
    private final JCheckBox chkJwkInject = new JCheckBox("jwk Self-Sign", true);
    private final JCheckBox chkClaimTamper = new JCheckBox("Claim Tampering", true);
    private final JCheckBox chkExpiry = new JCheckBox("Expiry Manipulation", true);
    private final JCheckBox chkNullSig = new JCheckBox("Null Signature", true);
    private final JCheckBox chkCrossService = new JCheckBox("Cross-Service Relay", true);
    private final JCheckBox chkNestedJwt = new JCheckBox("Nested JWT Analysis", true);

    // Brute-force config
    private final JComboBox<String> wordlistCombo = new JComboBox<>(new String[]{
            "Built-in Top 500 Secrets",
            "Built-in + Custom File",
            "Custom File Only"
    });
    private final JTextField customWordlistPath = new JTextField(20);
    private final JButton browseBtn = new JButton("Browse...");
    private final JSpinner threadsSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 100, 5));

    // Action buttons
    private final JButton decodeBtn = new JButton("🔍 Decode Token");
    private final JButton attackBtn = new JButton("🚀 Launch Attack");
    private final JButton cancelBtn = new JButton("⏹ Cancel");
    private final JButton clearBtn = new JButton("🗑 Clear All");
    private final JButton exportBtn = new JButton("📤 Export CSV");
    private final JLabel statusLabel = new JLabel("Ready — Paste a JWT token to begin");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel summaryLabel = new JLabel("Attacks: 0 | Findings: 0 | BF Keys Tested: 0");

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
                "🔐 JWT Token Input & Decode",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 12),
                new Color(88, 166, 255)));

        // Input row
        JPanel inputRow = new JPanel(new BorderLayout(6, 0));
        tokenInputArea.setToolTipText("Paste a JWT token (e.g., eyJhbGciOi...) or an HTTP request containing a Bearer token");
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

        JButton pasteBtn = new JButton("📋 Paste");
        pasteBtn.addActionListener(e -> {
            try {
                String clipboard = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
                tokenInputArea.setText(clipboard);
                onDecode();
            } catch (Exception ex) {
                statusLabel.setText("⚠️ Clipboard empty or inaccessible");
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
        JPanel sigPanel = wrapWithTitle("Signature & Info", signatureInfoArea, new Color(255, 166, 87));
        decodePanels.add(sigPanel);

        topSection.add(decodePanels, BorderLayout.CENTER);

        // ========== SECTION 2: Attack Configuration ==========
        JPanel configSection = new JPanel(new BorderLayout(6, 4));
        configSection.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(248, 81, 73), 1),
                "⚔️ Attack Configuration",
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

        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.addActionListener(e -> setAllAttacks(true));
        JButton deselectAllBtn = new JButton("Deselect All");
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
        String[] columnNames = {"#", "Severity", "Attack Type", "Modified Token", "Status", "Details"};
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
        JMenuItem copyToken = new JMenuItem("📋 Copy Modified Token");
        copyToken.addActionListener(e -> copyCell(3));
        JMenuItem copyDetails = new JMenuItem("📋 Copy Details");
        copyDetails.addActionListener(e -> copyCell(5));
        JMenuItem sendToRepeater = new JMenuItem("🔁 Send Token to Clipboard (for Repeater)");
        sendToRepeater.addActionListener(e -> {
            int row = resultsTable.getSelectedRow();
            if (row >= 0) {
                String token = String.valueOf(resultsTable.getValueAt(row, 3));
                copyToClipboard(token);
                statusLabel.setText("✅ Token copied — paste it in Burp Repeater Authorization header.");
            }
        });
        popup.add(copyToken);
        popup.add(copyDetails);
        popup.addSeparator();
        popup.add(sendToRepeater);
        resultsTable.setComponentPopupMenu(popup);

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(255, 200, 55), 1),
                "🎯 Attack Results",
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
                "📜 Live Attack Audit Log",
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
            statusLabel.setText("⚠️ Paste a JWT token first!");
            return;
        }

        // Try to extract JWT from raw HTTP request or plain text
        String extracted = JwtToken.extractFromRequest(raw);
        if (extracted == null) {
            // Maybe it's a direct token
            if (JwtToken.isJwt(raw)) {
                extracted = raw;
            } else {
                statusLabel.setText("❌ No valid JWT found in input.");
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

            statusLabel.setText("✅ JWT decoded successfully — " + currentToken.algorithm() + " | " +
                    (currentToken.isExpired() ? "⚠️ EXPIRED" : "Valid"));

            log("[JWT-DECODE] Token parsed: alg=" + currentToken.algorithm() +
                    ", sub=" + currentToken.subject() +
                    ", exp=" + (currentToken.expiration() > 0 ? new java.util.Date(currentToken.expiration() * 1000L) : "N/A") +
                    ", expired=" + currentToken.isExpired());

        } catch (Exception e) {
            statusLabel.setText("❌ Parse error: " + e.getMessage());
            log("[JWT-DECODE] ❌ Failed to parse: " + e.getMessage());
            currentToken = null;
        }
    }

    private void onLaunchAttack() {
        if (currentToken == null) {
            onDecode();
            if (currentToken == null) {
                statusLabel.setText("⚠️ Decode a valid JWT first!");
                return;
            }
        }

        cancelled = false;
        attackBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("⚔️ Launching JWT attacks...");
        resultsModel.setRowCount(0);

        scanState.info("burpinho [JWT]: Starting JWT attack suite on " + currentToken.algorithm() + " token");

        threadPool.submit(() -> {
            try {
                runAttacks();
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("❌ Attack error: " + t.getMessage()));
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

            final int id = resultsModel.getRowCount() + 1;
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
            log("[JWT-BRUTE] Starting HMAC Secret Brute-Force...");
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
                    statusLabel.setText(String.format("🔑 BF: %,d/%,d (%.0f keys/sec)",
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
                    log("[JWT-BRUTE] ⚠️ Custom wordlist file not found, falling back to built-in.");
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

                SwingUtilities.invokeLater(() -> {
                    int id = resultsModel.getRowCount() + 1;
                    resultsModel.addRow(new Object[]{
                            id, "CRITICAL",
                            "HMAC BF (secret=\"" + crackedSecret + "\")",
                            resignedToken.length() > 60 ? resignedToken.substring(0, 60) + "..." : resignedToken,
                            "🔥 CRACKED",
                            "Secret cracked: \"" + crackedSecret + "\" — " + bfResult.summary()
                    });
                });
            } else {
                SwingUtilities.invokeLater(() -> {
                    int id = resultsModel.getRowCount() + 1;
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
            statusLabel.setText("✅ JWT attack suite completed — " + fc + " critical/high findings.");
            summaryLabel.setText("Attacks: " + ac + " | Critical/High: " + fc + " | BF Keys Tested: " + bfk);
            scanState.info("burpinho [JWT]: Attack suite complete — " + ac + " results, " + fc + " critical/high.");
        });
    }

    private void onCancel() {
        cancelled = true;
        if (activeBruteForcer != null) {
            activeBruteForcer.cancel();
        }
        statusLabel.setText("⏹ Attack cancelled.");
        scanState.info("burpinho [JWT]: Attack cancelled by user.");
    }

    private void onClear() {
        resultsModel.setRowCount(0);
        logArea.setText("");
        headerArea.setText("");
        payloadArea.setText("");
        signatureInfoArea.setText("");
        tokenInputArea.setText("");
        currentToken = null;
        statusLabel.setText("Ready — Paste a JWT token to begin");
        summaryLabel.setText("Attacks: 0 | Findings: 0 | BF Keys Tested: 0");
    }

    private void onBrowseWordlist() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select JWT Secret Wordlist File");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            customWordlistPath.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void onExportCsv() {
        if (resultsModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "No JWT attack results to export!", "Export", JOptionPane.WARNING_MESSAGE);
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
                JOptionPane.showMessageDialog(this, "Exported to " + f.getAbsolutePath(), "Export", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // =====================================================================
    //  PUBLIC API (for context menu integration)
    // =====================================================================

    /**
     * Set token from external source (e.g., context menu / Repeater).
     */
    public void setToken(String rawTokenOrRequest) {
        tokenInputArea.setText(rawTokenOrRequest);
        onDecode();
    }

    /**
     * Set the full HTTP request and auto-extract JWT.
     */
    public void setHttpRequest(String httpRequest) {
        String jwt = JwtToken.extractFromRequest(httpRequest);
        if (jwt != null) {
            tokenInputArea.setText(jwt);
            onDecode();
        } else {
            tokenInputArea.setText(httpRequest);
            statusLabel.setText("⚠️ No JWT detected in request — try pasting the token directly.");
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
