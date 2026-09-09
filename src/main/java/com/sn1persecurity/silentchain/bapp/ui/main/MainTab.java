package com.sn1persecurity.silentchain.bapp.ui.main;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.export.CsvExporter;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.ui.dialogs.DataConsentDialog;
import com.sn1persecurity.silentchain.bapp.ui.modules.ExploitPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.FuzzerPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.IpScanPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.ReconPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.ReportPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.SqliPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.VulnScannerPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.XssPanel;

import javax.swing.BoxLayout;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.Timer;
import java.awt.BorderLayout;

/**
 * Root burpinho tab — tabbed layout with 9 dedicated modules:
 *   Tab 1: Passive AI
 *   Tab 2: Recon (Subdomain & IP)
 *   Tab 3: IP & Network Scanner
 *   Tab 4: Vulnerability Scanner
 *   Tab 5: XSS Analyzer
 *   Tab 6: SQLi Analyzer
 *   Tab 7: Path Fuzzer
 *   Tab 8: Exploit & PoC Advisor
 *   Tab 9: Report Generator
 */
public class MainTab extends JPanel implements ControlBar.Actions {

    private final MontoyaApi api;
    private final Settings settings;
    private final SettingsPersistence persistence;
    private final ScanState scanState;
    private final TaskRegistry taskRegistry;
    private final FindingsRegistry findingsRegistry;
    private Runnable settingsOpener;

    private final StatisticsPanel statisticsPanel;
    private final RuntimeStatusLine runtimeStatusLine;
    private final ControlBar controlBar;
    private final TaskTablePanel taskTablePanel;
    private final FindingsTablePanel findingsTablePanel;
    private final ConsolePane consolePane;

    // Module panels
    private ReconPanel reconPanel;
    private IpScanPanel ipScanPanel;
    private VulnScannerPanel vulnScannerPanel;
    private XssPanel xssPanel;
    private SqliPanel sqliPanel;
    private FuzzerPanel fuzzerPanel;
    private ExploitPanel exploitPanel;
    private ReportPanel reportPanel;
    private final JTabbedPane moduleTabs;

    public MainTab(MontoyaApi api,
                   Settings settings,
                   SettingsPersistence persistence,
                   ScanState scanState,
                   Counters counters,
                   TaskRegistry taskRegistry,
                   FindingsRegistry findingsRegistry) {
        super(new BorderLayout());
        this.api = api;
        this.settings = settings;
        this.persistence = persistence;
        this.scanState = scanState;
        this.taskRegistry = taskRegistry;
        this.findingsRegistry = findingsRegistry;

        this.statisticsPanel = new StatisticsPanel(counters);
        this.runtimeStatusLine = new RuntimeStatusLine(settings, scanState);
        this.controlBar = new ControlBar(settings, scanState, this);
        this.taskTablePanel = new TaskTablePanel(taskRegistry);
        this.findingsTablePanel = new FindingsTablePanel(findingsRegistry);
        this.consolePane = new ConsolePane(settings.theme());

        // ---- Build passive analysis panel (Tab 1) ----
        JPanel passivePanel = new JPanel(new BorderLayout());

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(new MainHeader());
        north.add(statisticsPanel);
        north.add(runtimeStatusLine);
        north.add(controlBar);

        JSplitPane center = new JSplitPane(JSplitPane.VERTICAL_SPLIT, taskTablePanel, findingsTablePanel);
        center.setResizeWeight(0.4);
        center.setDividerLocation(220);

        passivePanel.add(north, BorderLayout.NORTH);
        passivePanel.add(center, BorderLayout.CENTER);
        passivePanel.add(consolePane, BorderLayout.SOUTH);

        // ---- Build tabbed pane ----
        moduleTabs = new JTabbedPane();
        moduleTabs.addTab("Passive AI", passivePanel);

        add(moduleTabs, BorderLayout.CENTER);

        // Bridge the console log so ScanState.info/debug/error mirror into the pane.
        scanState.setConsoleSink(consolePane::append);

        startRefreshTimer();
        refreshNow();
    }

    /**
     * Wire all module panels after construction.
     */
    public void setModulePanels(ReconPanel recon,
                                IpScanPanel ipScan,
                                VulnScannerPanel vulnScanner,
                                XssPanel xss,
                                SqliPanel sqli,
                                FuzzerPanel fuzzer,
                                ExploitPanel exploit,
                                ReportPanel report) {
        this.reconPanel = recon;
        this.ipScanPanel = ipScan;
        this.vulnScannerPanel = vulnScanner;
        this.xssPanel = xss;
        this.sqliPanel = sqli;
        this.fuzzerPanel = fuzzer;
        this.exploitPanel = exploit;
        this.reportPanel = report;

        moduleTabs.addTab("Recon (Subdomain & IP)", recon);
        moduleTabs.addTab("IP & Network Scanner", ipScan);
        moduleTabs.addTab("Vulnerability Scanner", vulnScanner);
        moduleTabs.addTab("XSS Analyzer", xss);
        moduleTabs.addTab("SQLi Analyzer", sqli);
        moduleTabs.addTab("Path Fuzzer", fuzzer);
        moduleTabs.addTab("Exploit & PoC", exploit);
        moduleTabs.addTab("Report Generator", report);
    }

    public ReconPanel getReconPanel()               { return reconPanel; }
    public IpScanPanel getIpScanPanel()             { return ipScanPanel; }
    public VulnScannerPanel getVulnScannerPanel()   { return vulnScannerPanel; }
    public XssPanel getXssPanel()                   { return xssPanel; }
    public SqliPanel getSqliPanel()                 { return sqliPanel; }
    public FuzzerPanel getFuzzerPanel()             { return fuzzerPanel; }
    public ExploitPanel getExploitPanel()           { return exploitPanel; }
    public ReportPanel getReportPanel()             { return reportPanel; }

    public void switchToTab(int index) {
        if (index >= 0 && index < moduleTabs.getTabCount()) {
            moduleTabs.setSelectedIndex(index);
        }
    }

    private void startRefreshTimer() {
        Timer timer = new Timer(1500, e -> refreshNow());
        timer.setInitialDelay(500);
        timer.start();
    }

    private void refreshNow() {
        statisticsPanel.refresh();
        runtimeStatusLine.refresh();
        controlBar.refresh();
        taskTablePanel.refresh();
        findingsTablePanel.refresh();
    }

    public void applyTheme() {
        consolePane.applyTheme(settings.theme());
    }

    public void setSettingsOpener(Runnable opener) {
        this.settingsOpener = opener;
    }

    public void onSettingsSaved() {
        applyTheme();
        refreshNow();
    }

    // ---- ControlBar.Actions implementation ----

    @Override
    public void onSettings() {
        if (settingsOpener != null) {
            settingsOpener.run();
        }
    }

    @Override
    public void onToggleScanning() {
        if (!settings.passiveEnabled()) {
            // Turning ON: check consent
            if (!DataConsentDialog.ensureConsent(api, persistence)) {
                scanState.info("Passive scanning cancelled (consent required).");
                return;
            }
            settings.setPassiveEnabled(true);
            persistence.save(settings);
            scanState.info("Passive scanning ENABLED.");
        } else {
            // Turning OFF
            settings.setPassiveEnabled(false);
            persistence.save(settings);
            scanState.info("Passive scanning DISABLED.");
        }
        refreshNow();
    }

    @Override
    public void onClearCompleted() {
        taskRegistry.clearCompleted();
        refreshNow();
    }

    @Override
    public void onCancelAll() {
        int count = taskRegistry.cancelAll();
        scanState.info("Cancelled " + count + " active task(s).");
        refreshNow();
    }

    @Override
    public void onTogglePause() {
        boolean next = !scanState.isPaused();
        scanState.setPaused(next);
        scanState.info("Scanning " + (next ? "PAUSED" : "RESUMED") + ".");
        refreshNow();
    }

    @Override
    public void onExportCsv() {
        String path = CsvExporter.export(this, findingsRegistry);
        if (path != null) {
            scanState.info("Exported findings to " + path);
        }
    }

    @Override
    public void onToolStatus() {
        JOptionPane.showMessageDialog(this,
                "burpinho v3.2.0 — 100% Self-Contained Pure Java Architecture.\n\n" +
                "All core engines (Recon, IP/CIDR Scanner, Vulnerability Scanner, XSS,\n" +
                "SQLi, Path Fuzzer, and Reports) are natively built-in.\n" +
                "No external Go, Python, or CLI installations required for full operation.",
                "Tool Status", JOptionPane.INFORMATION_MESSAGE);
    }
}
