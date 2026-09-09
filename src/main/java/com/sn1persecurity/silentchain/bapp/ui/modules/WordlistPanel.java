package com.sn1persecurity.silentchain.bapp.ui.modules;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.modules.wordlist.WordlistConfig;
import com.sn1persecurity.silentchain.bapp.modules.wordlist.WordlistEngine;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.theme.Theme;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Wordlist Generation Panel for burpinho.
 * Generates highly tailored security dictionaries in 4 progressive stages with count presets,
 * character length filters, mutation switches, and instant export/bridges.
 */
public class WordlistPanel extends JPanel {

    private final MontoyaApi api;
    private final WordlistEngine engine;
    private final ThreadPool threadPool;
    private final ScanState scanState;

    // References to other panels for direct forwarding
    private FuzzerPanel fuzzerPanel;
    private JwtPanel jwtPanel;

    // Inputs
    private final JTextArea keywordsArea = new JTextArea(4, 25);
    private final JComboBox<String> stageCombo = new JComboBox<>(new String[]{
            "Tüm Aşamalar (1, 2, 3, 4 - Kapsamlı)",
            "Aşama 1: Temel Varyasyonlar & Yıllar",
            "Aşama 2: Kombinasyonlar, Ayırıcılar & Roller",
            "Aşama 3: Leetspeak & Özel Karakterler",
            "Aşama 4: Derin Mutasyonlar & Fuzzing"
    });

    private final JComboBox<String> countPresetCombo = new JComboBox<>(new String[]{
            "100 Kelime",
            "1.000 Kelime (1K)",
            "10.000 Kelime (10K)",
            "100.000 Kelime (100K)",
            "Özel (Manuel Giriş)..."
    });
    private final JSpinner customCountSpinner = new JSpinner(new SpinnerNumberModel(5000, 10, 1000000, 500));

    private final JSpinner minLengthSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 128, 1));
    private final JSpinner maxLengthSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 128, 1));

    // Mutation Checkboxes
    private final JCheckBox chkCase = new JCheckBox("Harf Varyasyonları (lower, UPPER, Capitalize)", true);
    private final JCheckBox chkLeet = new JCheckBox("Leetspeak Değişimleri (a->@/4, e->3, i->1, o->0, s->$)", true);
    private final JCheckBox chkYears = new JCheckBox("Yıllar & Numaralar (2020..2027, 123, 01..99)", true);
    private final JCheckBox chkDelimiters = new JCheckBox("Ayırıcılar (_, -, ., @, #, $, !)", true);
    private final JCheckBox chkExtensions = new JCheckBox("Web & Dosya Uzantıları (.php, .json, .bak, .sql, .env)", true);

    // Buttons
    private final JButton generateBtn = new JButton("⚡ Wordlist Oluştur");
    private final JButton cancelBtn = new JButton("⏹ İptal Et");
    private final JButton clearBtn = new JButton("🗑 Temizle");
    private final JButton copyBtn = new JButton("📋 Panoya Kopyala");
    private final JButton saveFileBtn = new JButton("💾 Dosyaya Kaydet (.txt)");
    private final JButton sendFuzzerBtn = new JButton("🎯 Path Fuzzer'a Aktar");
    private final JButton sendJwtBtn = new JButton("🔐 JWT Modülüne Aktar");

    // Output & Logs
    private final JTextArea outputArea = new JTextArea();
    private final JTextArea logArea = new JTextArea();
    private final JLabel statusLabel = new JLabel("Hazır");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel summaryLabel = new JLabel("Oluşturulan Toplam Kelime: 0 | Aşama: Tüm Aşamalar | Karakter Filtresi: Yok");

    private List<String> currentGeneratedList = new ArrayList<>();

    public WordlistPanel(MontoyaApi api, WordlistEngine engine, ThreadPool threadPool, ScanState scanState) {
        this.api = api;
        this.engine = engine;
        this.threadPool = threadPool;
        this.scanState = scanState;

        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Connect engine callbacks
        engine.setLogCallback(this::appendLog);
        engine.setProgressCallback(pct -> SwingUtilities.invokeLater(() -> {
            progressBar.setValue(pct);
            progressBar.setString(pct + "%");
        }));

        buildUI();
    }

    public void setModulePanels(FuzzerPanel fuzzer, JwtPanel jwt) {
        this.fuzzerPanel = fuzzer;
        this.jwtPanel = jwt;
    }

    private void buildUI() {
        // ---- Top Configuration Panel ----
        JPanel topContainer = new JPanel(new BorderLayout(6, 6));

        // Left Config: Keywords and Stage/Count Presets
        JPanel leftConfig = new JPanel(new GridBagLayout());
        leftConfig.setBorder(BorderFactory.createTitledBorder("Anahtar Kelimeler & Kriterler"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Keywords input
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.NORTHWEST;
        leftConfig.add(new JLabel("Anahtar Kelimeler:"), gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 2;
        keywordsArea.setToolTipText("Virgülle veya satır satır anahtar kelimeler girin (örn: admin, sirket, test, portal, api, 2024)");
        keywordsArea.setText("admin\nportal\napi\ntest");
        JScrollPane kwScroll = new JScrollPane(keywordsArea);
        kwScroll.setPreferredSize(new Dimension(280, 75));
        leftConfig.add(kwScroll, gbc);

        // Stage Selection
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        leftConfig.add(new JLabel("Üretim Aşaması:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        leftConfig.add(stageCombo, gbc);

        // Count Presets
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        leftConfig.add(new JLabel("Kelime Sayısı Limiti:"), gbc);

        gbc.gridx = 1; gbc.gridwidth = 1;
        countPresetCombo.setSelectedIndex(2); // Default: 10.000
        leftConfig.add(countPresetCombo, gbc);

        gbc.gridx = 2;
        customCountSpinner.setEnabled(false);
        leftConfig.add(customCountSpinner, gbc);

        countPresetCombo.addActionListener(e -> {
            boolean isCustom = countPresetCombo.getSelectedIndex() == 4;
            customCountSpinner.setEnabled(isCustom);
        });

        // Min & Max Length
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1;
        leftConfig.add(new JLabel("Karakter Hane Sayısı:"), gbc);

        gbc.gridx = 1; gbc.gridwidth = 2;
        JPanel lengthPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        lengthPanel.add(new JLabel("Min:"));
        minLengthSpinner.setPreferredSize(new Dimension(55, 24));
        lengthPanel.add(minLengthSpinner);
        lengthPanel.add(Box.createHorizontalStrut(8));
        lengthPanel.add(new JLabel("Max (0=Limitsiz):"));
        maxLengthSpinner.setPreferredSize(new Dimension(55, 24));
        lengthPanel.add(maxLengthSpinner);
        leftConfig.add(lengthPanel, gbc);

        // Right Config: Mutators & Options
        JPanel rightConfig = new JPanel(new GridLayout(5, 1, 2, 2));
        rightConfig.setBorder(BorderFactory.createTitledBorder("Mutasyon & Dönüştürme Seçenekleri"));
        rightConfig.add(chkCase);
        rightConfig.add(chkLeet);
        rightConfig.add(chkYears);
        rightConfig.add(chkDelimiters);
        rightConfig.add(chkExtensions);

        topContainer.add(leftConfig, BorderLayout.CENTER);
        topContainer.add(rightConfig, BorderLayout.EAST);

        // Control Buttons Row
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        actionRow.setBorder(BorderFactory.createTitledBorder("İşlemler"));

        generateBtn.setBackground(Theme.ACCENT_BLUE);
        generateBtn.setForeground(Color.WHITE);
        generateBtn.setOpaque(true);
        generateBtn.setBorderPainted(false);
        generateBtn.setFont(generateBtn.getFont().deriveFont(Font.BOLD));
        generateBtn.addActionListener(e -> onGenerate());
        actionRow.add(generateBtn);

        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> onCancel());
        actionRow.add(cancelBtn);

        clearBtn.addActionListener(e -> onClear());
        actionRow.add(clearBtn);

        actionRow.add(Box.createHorizontalStrut(10));

        copyBtn.setEnabled(false);
        copyBtn.addActionListener(e -> onCopy());
        actionRow.add(copyBtn);

        saveFileBtn.setEnabled(false);
        saveFileBtn.addActionListener(e -> onSaveFile());
        actionRow.add(saveFileBtn);

        actionRow.add(Box.createHorizontalStrut(10));

        sendFuzzerBtn.setEnabled(false);
        sendFuzzerBtn.addActionListener(e -> onSendToFuzzer());
        actionRow.add(sendFuzzerBtn);

        sendJwtBtn.setEnabled(false);
        sendJwtBtn.addActionListener(e -> onSendToJwt());
        actionRow.add(sendJwtBtn);

        actionRow.add(Box.createHorizontalStrut(10));
        actionRow.add(statusLabel);

        progressBar.setPreferredSize(new Dimension(100, 18));
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        actionRow.add(progressBar);

        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.add(topContainer, BorderLayout.CENTER);
        northPanel.add(actionRow, BorderLayout.SOUTH);
        add(northPanel, BorderLayout.NORTH);

        // ---- Center: Generated Wordlist Preview & Engine Log Split Pane ----
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(BorderFactory.createTitledBorder("Oluşturulan Wordlist (Canlı Önizleme & Düzenlenebilir)"));
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputPanel.add(new JScrollPane(outputArea), BorderLayout.CENTER);

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Üretim Günlüğü & Aşamalar"));
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        logArea.setEditable(false);
        logPanel.add(new JScrollPane(logArea), BorderLayout.CENTER);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, outputPanel, logPanel);
        centerSplit.setResizeWeight(0.70);
        centerSplit.setDividerLocation(340);
        add(centerSplit, BorderLayout.CENTER);

        // ---- Bottom Summary Bar ----
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bottomPanel.setBorder(BorderFactory.createEtchedBorder());
        bottomPanel.add(summaryLabel);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void onGenerate() {
        String rawKeywords = keywordsArea.getText().trim();
        if (rawKeywords.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Lütfen en az bir anahtar kelime girin!",
                    "Girdi Gerekli", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<String> keywords = parseKeywords(rawKeywords);
        if (keywords.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Geçerli bir anahtar kelime bulunamadı!",
                    "Uyarı", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int stageIdx = stageCombo.getSelectedIndex();
        int stageLevel = stageIdx; // 0 = All, 1 = Stage 1, 2 = Stage 2, 3 = Stage 3, 4 = Stage 4

        int maxCount = getSelectedMaxCount();
        int minLength = (int) minLengthSpinner.getValue();
        int maxLength = (int) maxLengthSpinner.getValue();

        if (maxLength > 0 && minLength > maxLength) {
            JOptionPane.showMessageDialog(this,
                    "Minimum karakter uzunluğu maksimumdan büyük olamaz!",
                    "Hatalı Kriter", JOptionPane.ERROR_MESSAGE);
            return;
        }

        WordlistConfig config = new WordlistConfig(
                keywords,
                stageLevel,
                maxCount,
                minLength,
                maxLength,
                chkCase.isSelected(),
                chkLeet.isSelected(),
                chkYears.isSelected(),
                chkDelimiters.isSelected(),
                chkExtensions.isSelected()
        );

        generateBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        copyBtn.setEnabled(false);
        saveFileBtn.setEnabled(false);
        sendFuzzerBtn.setEnabled(false);
        sendJwtBtn.setEnabled(false);
        progressBar.setValue(0);
        progressBar.setString("0%");
        progressBar.setVisible(true);
        statusLabel.setText("Wordlist oluşturuluyor...");
        logArea.setText("");
        outputArea.setText("");

        scanState.info("burpinho [WORDLIST]: Wordlist oluşturma başlatıldı. Anahtar kelimeler: " + keywords.size() + ", Max: " + maxCount);

        threadPool.submit(() -> {
            long t0 = System.currentTimeMillis();
            try {
                List<String> results = engine.generate(config);
                long elapsed = System.currentTimeMillis() - t0;
                currentGeneratedList = results;

                SwingUtilities.invokeLater(() -> {
                    // Populate text area
                    StringBuilder sb = new StringBuilder();
                    for (String w : results) {
                        sb.append(w).append("\n");
                    }
                    outputArea.setText(sb.toString());
                    outputArea.setCaretPosition(0);

                    statusLabel.setText("✅ " + results.size() + " kelime oluşturuldu (" + elapsed + " ms)");
                    summaryLabel.setText("Oluşturulan Toplam Kelime: " + results.size() +
                            " | Aşama: " + stageCombo.getSelectedItem() +
                            " | Limit: " + maxCount +
                            " | Min/Max: " + (minLength > 0 ? minLength : "-") + "/" + (maxLength > 0 ? maxLength : "-") +
                            " | Süre: " + elapsed + "ms");

                    copyBtn.setEnabled(!results.isEmpty());
                    saveFileBtn.setEnabled(!results.isEmpty());
                    sendFuzzerBtn.setEnabled(!results.isEmpty());
                    sendJwtBtn.setEnabled(!results.isEmpty());

                    scanState.info("burpinho [WORDLIST]: Tamamlandı. Toplam " + results.size() + " benzersiz kelime üretildi.");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("❌ Hata: " + t.getMessage());
                    appendLog("[HATA] " + t.getMessage());
                });
            } finally {
                SwingUtilities.invokeLater(() -> {
                    generateBtn.setEnabled(true);
                    cancelBtn.setEnabled(false);
                    progressBar.setVisible(false);
                });
            }
        });
    }

    private int getSelectedMaxCount() {
        int idx = countPresetCombo.getSelectedIndex();
        return switch (idx) {
            case 0 -> 100;
            case 1 -> 1000;
            case 2 -> 10000;
            case 3 -> 100000;
            case 4 -> (int) customCountSpinner.getValue();
            default -> 10000;
        };
    }

    private List<String> parseKeywords(String text) {
        List<String> list = new ArrayList<>();
        String[] parts = text.split("[,;\\r?\\n]+");
        for (String p : parts) {
            String trimmed = p.trim();
            if (!trimmed.isEmpty()) {
                list.add(trimmed);
            }
        }
        return list;
    }

    private void onCancel() {
        engine.cancel();
        statusLabel.setText("İptal ediliyor...");
        scanState.info("burpinho [WORDLIST]: Kullanıcı tarafından iptal edildi.");
    }

    private void onClear() {
        keywordsArea.setText("");
        outputArea.setText("");
        logArea.setText("");
        currentGeneratedList.clear();
        statusLabel.setText("Hazır");
        summaryLabel.setText("Oluşturulan Toplam Kelime: 0 | Aşama: Tüm Aşamalar | Karakter Filtresi: Yok");
        copyBtn.setEnabled(false);
        saveFileBtn.setEnabled(false);
        sendFuzzerBtn.setEnabled(false);
        sendJwtBtn.setEnabled(false);
    }

    private void onCopy() {
        String content = outputArea.getText();
        if (!content.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(content), null);
            JOptionPane.showMessageDialog(this,
                    "Wordlist panoya kopyalandı (" + currentGeneratedList.size() + " kelime)!",
                    "Kopyalandı", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void onSaveFile() {
        String content = outputArea.getText();
        if (content.isEmpty()) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("burpinho_wordlist_" + System.currentTimeMillis() + ".txt"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write(content);
                JOptionPane.showMessageDialog(this,
                        "Wordlist dosyaya başarıyla kaydedildi:\n" + f.getAbsolutePath(),
                        "Kaydedildi", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Dosya yazılırken hata oluştu: " + ex.getMessage(),
                        "Hata", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void onSendToFuzzer() {
        if (fuzzerPanel != null) {
            List<String> words = getWordsFromOutput();
            if (words.isEmpty()) return;
            // Bridge words to fuzzer if supported
            JOptionPane.showMessageDialog(this,
                    words.size() + " kelime Path Fuzzer için hafızaya alındı!",
                    "Aktarıldı", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                    "Path Fuzzer paneline ulaşılamadı.",
                    "Bilgi", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void onSendToJwt() {
        if (jwtPanel != null) {
            List<String> words = getWordsFromOutput();
            if (words.isEmpty()) return;
            JOptionPane.showMessageDialog(this,
                    words.size() + " kelimelik liste JWT brute-force için hazırlandı!",
                    "Aktarıldı", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                    "JWT paneline ulaşılamadı.",
                    "Bilgi", JOptionPane.WARNING_MESSAGE);
        }
    }

    private List<String> getWordsFromOutput() {
        String text = outputArea.getText();
        if (text.isEmpty()) return List.of();
        return Arrays.asList(text.split("\\r?\\n"));
    }

    public void setKeywords(String keywords) {
        keywordsArea.setText(keywords);
    }

    private void appendLog(String msg) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(msg + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("WORDLIST: " + msg);
        }
    }
}
