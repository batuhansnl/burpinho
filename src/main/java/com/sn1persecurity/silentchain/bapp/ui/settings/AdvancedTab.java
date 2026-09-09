package com.sn1persecurity.silentchain.bapp.ui.settings;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.diag.TaskDiagnosticsReport;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/**
 * Advanced settings tab — Community items (silentchain_ai_community.py:
 * 1507-1623) plus the Phase-4 safety rails grouped in their own section so the
 * BApp additions are visible.
 */
public class AdvancedTab extends JPanel {

    private final Settings settings;
    private final ScanState scanState;
    private final TaskRegistry taskRegistry;

    private final JCheckBox passiveScanning = new JCheckBox("Otomatik pasif taramayı etkinleştir");
    private final JComboBox<String> consoleTheme = new JComboBox<>(new String[]{"Açık (Light)", "Koyu (Dark)"});
    private final JCheckBox verboseLogging = new JCheckBox("Ayrıntılı günlük kaydı (Verbose)");
    private final JTextField requestTimeout = new JTextField(8);

    private final JCheckBox sanitizer = new JCheckBox("AI'ya göndermeden önce secret / PII verilerini maskele");
    private final JCheckBox inScopeOnly = new JCheckBox("Sadece hedef kapsamındaki (in-scope) isteklerle sınırla");
    private final JTextField maxResponseKb = new JTextField(8);
    private final JTextField hostRpm = new JTextField(8);
    private final JTextField dedupMinutes = new JTextField(8);

    public AdvancedTab(Settings settings, ScanState scanState, TaskRegistry taskRegistry) {
        this.settings = settings;
        this.scanState = scanState;
        this.taskRegistry = taskRegistry;

        setLayout(new GridBagLayout());

        int row = 0;
        addRow(row++, "Pasif Tarama:", passiveScanning);
        addRow(row++, "Konsol Teması:", consoleTheme);
        addRow(row++, "Ayrıntılı Loglama:", verboseLogging);
        addRow(row++, "AI İstek Zaman Aşımı (sn):", requestTimeout);

        JButton diagBtn = new JButton("Görev Tanılamasını Çalıştır");
        diagBtn.addActionListener(e -> scanState.info(TaskDiagnosticsReport.generate(taskRegistry)));
        addRow(row++, "", diagBtn);

        addSection(row++, "Güvenlik Rayları & Sınırlar (Safety Rails)");
        addRow(row++, "Sanitizer:", sanitizer);
        addRow(row++, "Scope (Kapsam):", inScopeOnly);
        addRow(row++, "Maksimum Yanıt Boyutu (KB):", maxResponseKb);
        addRow(row++, "Host Başına İstek/Dakika:", hostRpm);
        addRow(row++, "URL Tekilleştirme Süresi (dk):", dedupMinutes);

        addUpgradeNotice(row++);
    }

    // ---- Load / store -------------------------------------------------------

    public void load() {
        passiveScanning.setSelected(settings.passiveEnabled());
        consoleTheme.setSelectedItem(settings.theme() == Settings.ThemeChoice.DARK ? "Koyu (Dark)" : "Açık (Light)");
        verboseLogging.setSelected(settings.verbose());
        requestTimeout.setText(Integer.toString(settings.requestTimeoutSeconds()));

        sanitizer.setSelected(settings.sanitizerEnabled());
        inScopeOnly.setSelected(settings.inScopeOnly());
        maxResponseKb.setText(Integer.toString(settings.maxResponseBytes() / 1024));
        hostRpm.setText(Integer.toString(settings.hostRequestsPerMinute()));
        dedupMinutes.setText(Long.toString(settings.urlDedupTtlMillis() / 60_000L));
    }

    public void store() {
        settings.setPassiveEnabled(passiveScanning.isSelected());
        String selectedTheme = String.valueOf(consoleTheme.getSelectedItem());
        settings.setTheme(selectedTheme.contains("Dark") || selectedTheme.contains("Koyu")
                ? Settings.ThemeChoice.DARK : Settings.ThemeChoice.LIGHT);
        settings.setVerbose(verboseLogging.isSelected());
        settings.setRequestTimeoutSeconds(parseInt(requestTimeout.getText(), settings.requestTimeoutSeconds()));

        settings.setSanitizerEnabled(sanitizer.isSelected());
        settings.setInScopeOnly(inScopeOnly.isSelected());
        settings.setMaxResponseBytes(parseInt(maxResponseKb.getText(), settings.maxResponseBytes() / 1024) * 1024);
        settings.setHostRequestsPerMinute(parseInt(hostRpm.getText(), settings.hostRequestsPerMinute()));
        settings.setUrlDedupTtlMillis(parseInt(dedupMinutes.getText(),
                (int) (settings.urlDedupTtlMillis() / 60_000L)) * 60_000L);
    }

    /** True if the passive-scanning checkbox is currently ticked. */
    public boolean passiveRequested() {
        return passiveScanning.isSelected();
    }

    public void setPassiveSelected(boolean v) {
        passiveScanning.setSelected(v);
    }

    // ---- Layout helpers -----------------------------------------------------

    private static int parseInt(String s, int fallback) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private void addRow(int row, String label, JComponent field) {
        GridBagConstraints lc = new GridBagConstraints();
        lc.gridx = 0; lc.gridy = row;
        lc.anchor = GridBagConstraints.WEST;
        lc.insets = new Insets(5, 8, 5, 8);
        add(new JLabel(label), lc);

        GridBagConstraints fc = new GridBagConstraints();
        fc.gridx = 1; fc.gridy = row;
        fc.anchor = GridBagConstraints.WEST;
        fc.fill = GridBagConstraints.HORIZONTAL;
        fc.weightx = 1.0;
        fc.insets = new Insets(5, 0, 5, 8);
        add(field, fc);
    }

    private void addSection(int row, String title) {
        JLabel label = new JLabel(title);
        label.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, label.getForeground()),
                BorderFactory.createEmptyBorder(6, 0, 2, 0)));
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        c.insets = new Insets(12, 8, 4, 8);
        add(label, c);
    }

    private void addUpgradeNotice(int row) {
        JTextArea notice = new JTextArea(
                "⚡ burpinho v4.0.0 — Çok Modüllü Güvenlik Paketi\n" +
                "Tüm modüller (Pasif AI, Keşif, IP Tarayıcı, Güvenlik Açığı Tarayıcısı,\n" +
                "XSS, SQLi, Fuzzer, Exploit & PoC, Raporlayıcı ve Gelişmiş JWT Saldırı Motoru)\n" +
                "yerel ve 100% bağımsız olarak çalışmaktadır.");
        notice.setEditable(false);
        notice.setOpaque(false);
        notice.setBorder(BorderFactory.createTitledBorder("Bilgi"));

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1.0; c.weighty = 1.0;
        c.insets = new Insets(12, 8, 8, 8);
        add(new JScrollPane(notice), c);
    }
}
