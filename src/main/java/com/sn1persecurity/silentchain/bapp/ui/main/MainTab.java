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
import com.sn1persecurity.silentchain.bapp.ui.modules.ReconPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.ScannerPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.ReportPanel;

import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Desktop;
import java.net.URI;

/**
 * Root burpinho tab — tabbed layout with modules:
 *   Tab 1: Passive AI Analysis (original layout)
 *   Tab 2: Recon (real tools: subfinder, httpx, naabu, etc.)
 *   Tab 3: Scanner (real tools: nuclei, dalfox, sqlmap, etc.)
 *   Tab 4: Report (HTML report generation)
 *
 * The original passive analysis tab is kept with:
 *   NORTH  : header + statistics + runtime status + control bar
 *   CENTER : vertical split — active tasks (top) / findings (bottom)
 *   SOUTH  : console pane
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

    // Module panels (set after construction via setters)
    private ReconPanel reconPanel;
    private ScannerPanel scannerPanel;
    private ReportPanel reportPanel;
    private JTabbedPane moduleTabs;

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

        // ---- Build passive analysis panel (original layout) ----
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
        // Recon, Scanner, Report tabs are added via setModulePanels()

        add(moduleTabs, BorderLayout.CENTER);

        // Bridge the console log so ScanState.info/debug/error mirror into the pane.
        scanState.setConsoleSink(consolePane::append);

        startRefreshTimer();
        refreshNow();
    }

    /**
     * Wire the module panels after construction (called from SilentchainExtension).
     * This avoids circular dependency during initialization.
     */
    public void setModulePanels(ReconPanel recon, ScannerPanel scanner, ReportPanel report) {
        this.reconPanel = recon;
        this.scannerPanel = scanner;
        this.reportPanel = report;
        moduleTabs.addTab("Recon", recon);
        moduleTabs.addTab("Scanner", scanner);
        moduleTabs.addTab("Report", report);
    }

    /** Get the recon panel for context menu integration. */
    public ReconPanel getReconPanel() { return reconPanel; }
    /** Get the scanner panel for context menu integration. */
    public ScannerPanel getScannerPanel() { return scannerPanel; }

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

    /** Re-apply the console theme (called after a Settings save changes it). */
    public void applyTheme() {
        consolePane.applyTheme(settings.theme());
    }

    /** Wire the Settings button to open the modal dialog (set post-construction). */
    public void setSettingsOpener(Runnable opener) {
        this.settingsOpener = opener;
    }

    /** Called after the Settings dialog saves: re-theme + refresh immediately. */
    public void onSettingsSaved() {
        applyTheme();
        refreshNow();
    }

    // ---- ControlBar.Actions -------------------------------------------------

    @Override
    public void onSettings() {
        if (settingsOpener != null) {
            settingsOpener.run();
        }
    }

    @Override
    public void onToggleScanning() {
        boolean now = !settings.passiveEnabled();

        // Consent gate when enabling passive analysis.
        if (now && !DataConsentDialog.ensureConsent(api, persistence)) {
            controlBar.refresh();
            scanState.info("burpinho: scanning not started (consent declined).");
            return;
        }

        settings.setPassiveEnabled(now);
        persistence.save(settings);
        controlBar.refresh();
        runtimeStatusLine.refresh();
        scanState.info("burpinho: passive scanning " + (now ? "STARTED" : "STOPPED") + ".");
    }

    @Override
    public void onClearCompleted() {
        int removed = taskRegistry.clearCompleted();
        taskTablePanel.refresh();
        scanState.info("burpinho: cleared " + removed + " completed task(s).");
    }

    @Override
    public void onCancelAll() {
        int cancelled = taskRegistry.cancelAll();
        taskTablePanel.refresh();
        scanState.info("burpinho: cancelled " + cancelled + " task(s).");
    }

    @Override
    public void onTogglePause() {
        boolean paused = scanState.togglePaused();
        controlBar.refresh();
        runtimeStatusLine.refresh();
        scanState.info("burpinho: tasks " + (paused ? "PAUSED" : "RESUMED") + ".");
    }

    @Override
    public void onExportCsv() {
        String path = CsvExporter.export(this, findingsRegistry);
        if (path != null) {
            scanState.info("burpinho: exported findings to " + path);
        } else {
            scanState.info("burpinho: CSV export cancelled or failed.");
        }
    }

    @Override
    public void onToolStatus() {
        // Switch to Recon tab to show tool status via settings
        if (settingsOpener != null) {
            settingsOpener.run();
        }
    }

    /** Convenience for registration. */
    public JComponent component() {
        return this;
    }
}
