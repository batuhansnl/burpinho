package com.sn1persecurity.silentchain.bapp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.ai.AiDispatcher;
import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.modules.exploit.ExploitModule;
import com.sn1persecurity.silentchain.bapp.modules.recon.ReconModule;
import com.sn1persecurity.silentchain.bapp.modules.report.ReportModule;
import com.sn1persecurity.silentchain.bapp.modules.scanner.ScannerModule;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.scan.AnalysisOrchestrator;
import com.sn1persecurity.silentchain.bapp.scan.PassiveHttpHandler;
import com.sn1persecurity.silentchain.bapp.scan.ScanGate;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.tools.ToolRegistry;
import com.sn1persecurity.silentchain.bapp.tools.ToolRunner;
import com.sn1persecurity.silentchain.bapp.ui.ContextMenuProvider;
import com.sn1persecurity.silentchain.bapp.ui.main.MainTab;
import com.sn1persecurity.silentchain.bapp.ui.modules.ReconPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.ReportPanel;
import com.sn1persecurity.silentchain.bapp.ui.modules.ScannerPanel;
import com.sn1persecurity.silentchain.bapp.ui.settings.SettingsDialog;
import com.sn1persecurity.silentchain.bapp.util.Banner;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.SwingUtilities;
import java.awt.Window;
import java.util.Set;

public class SilentchainExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "burpinho";
    public static final String EXTENSION_VERSION = "3.1.0";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        Banner.print(api);

        Settings settings = new Settings();
        SettingsPersistence persistence = new SettingsPersistence(api);
        persistence.load(settings);

        // ---- Live state ----------------------------------------------------
        Counters counters = new Counters();
        TaskRegistry taskRegistry = new TaskRegistry();
        FindingsRegistry findingsRegistry = new FindingsRegistry();
        ScanState scanState = new ScanState(api, settings);

        // ---- Tools infrastructure ------------------------------------------
        ToolRegistry toolRegistry = new ToolRegistry(api);
        ToolRunner toolRunner = new ToolRunner(api, toolRegistry);

        // Scan for installed tools in a background thread (non-blocking)
        Thread toolScan = new Thread(() -> toolRegistry.scanAll(), "burpinho-tool-scan");
        toolScan.setDaemon(true);
        toolScan.start();

        // ---- AI + pipeline -------------------------------------------------
        ThreadPool threadPool = new ThreadPool();
        MontoyaHttpClient http = new MontoyaHttpClient(api);
        AiDispatcher dispatcher = new AiDispatcher(api, http, settings, threadPool);
        AiService aiService = new AiService(api, threadPool, dispatcher);
        AnalysisOrchestrator orchestrator = new AnalysisOrchestrator(
                api, aiService, settings, scanState, counters, taskRegistry, findingsRegistry);

        // ---- Module engines ------------------------------------------------
        ReconModule reconModule = new ReconModule(api, toolRunner, toolRegistry);
        ScannerModule scannerModule = new ScannerModule(api, toolRunner, toolRegistry);
        ExploitModule exploitModule = new ExploitModule(api, toolRunner, toolRegistry, dispatcher);
        ReportModule reportModule = new ReportModule(api, dispatcher, findingsRegistry);

        // ---- Context menu (register early) ---------------------------------
        ContextMenuProvider contextMenu = new ContextMenuProvider(api, aiService, orchestrator, scanState);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // ---- HTTP handler --------------------------------------------------
        ScanGate gate = new ScanGate(api, settings);
        api.http().registerHttpHandler(
                new PassiveHttpHandler(api, gate, aiService, orchestrator, settings, scanState, counters)
        );

        // ---- UI ------------------------------------------------------------
        SwingUtilities.invokeLater(() -> {
            Window parent = api.userInterface().swingUtils().suiteFrame();

            MainTab mainTab = new MainTab(api, settings, persistence, scanState,
                    counters, taskRegistry, findingsRegistry);

            // Module panels
            ReconPanel reconPanel = new ReconPanel(api, reconModule, threadPool, scanState);
            ScannerPanel scannerPanel = new ScannerPanel(api, scannerModule, threadPool, scanState);
            ReportPanel reportPanel = new ReportPanel(api, reportModule, threadPool, scanState,
                    reconPanel::getLastResult, scannerPanel::getLastResult);

            mainTab.setModulePanels(reconPanel, scannerPanel, reportPanel);
            contextMenu.setModulePanels(reconPanel, scannerPanel);

            SettingsDialog settingsDialog = new SettingsDialog(parent, api, settings, persistence,
                    dispatcher, scanState, taskRegistry, toolRegistry, mainTab::onSettingsSaved);
            mainTab.setSettingsOpener(settingsDialog::showDialog);

            api.userInterface().registerSuiteTab("burpinho", mainTab);

            scanState.info(EXTENSION_NAME + " v" + EXTENSION_VERSION + " ready. "
                    + toolRegistry.statusSummary() + " | Passive scanning is "
                    + (settings.passiveEnabled() ? "ENABLED" : "DISABLED")
                    + " | Provider: " + settings.provider().displayName() + ".");
        });

        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput(EXTENSION_NAME + " unloading...");
            threadPool.shutdown();
        });
    }

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return Set.of(EnhancedCapability.AI_FEATURES);
    }
}

