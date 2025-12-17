package com.arqsz.burpgitleaks;

import java.util.List;

import com.arqsz.burpgitleaks.config.PluginSettings;
import com.arqsz.burpgitleaks.config.RuleLoader;
import com.arqsz.burpgitleaks.config.RuleLoader.GitleaksConfiguration;
import com.arqsz.burpgitleaks.scan.GitleaksScanCheck;
import com.arqsz.burpgitleaks.ui.GitleaksContextMenuProvider;
import com.arqsz.burpgitleaks.ui.SettingsTab;
import com.arqsz.burpgitleaks.ui.Toast;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

public class BurpExtender implements BurpExtension {

    private final String EXTENSION_NAME = "Gitleaks Integration";
    private final String EXTENSION_TAB_NAME = EXTENSION_NAME + " Settings";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        PluginSettings settings = new PluginSettings(api.persistence().preferences());

        ConfigResult configResult = loadInitialConfiguration(api, settings);
        GitleaksConfiguration config = configResult.config;

        var components = registerComponents(api, config, settings);

        handleStartupFeedback(api, config, components.settingsTab(), configResult.errorMsg());

        api.extension().registerUnloadingHandler(() -> {
            components.settingsTab().shutdown();
            components.menuProvider().shutdown();
        });

    }

    private record ConfigResult(GitleaksConfiguration config, String errorMsg) {
    }

    private record RegisteredComponents(SettingsTab settingsTab, GitleaksContextMenuProvider menuProvider) {
    }

    private ConfigResult loadInitialConfiguration(MontoyaApi api, PluginSettings settings) {
        GitleaksConfiguration config;
        String errorMsg = null;

        try {
            config = RuleLoader.loadConfiguration(null, api.logging(), settings.isDebugEnabled());
        } catch (Exception e) {
            api.logging().logToError("Fatal error loading bundled rules: " + e.getMessage());
            config = new GitleaksConfiguration(List.of(), List.of());
        }

        String customPath = settings.getCustomPath();
        if (customPath != null && !customPath.isBlank()) {
            try {
                config = RuleLoader.loadConfiguration(customPath, api.logging(), settings.isDebugEnabled());
                api.logging().logToOutput("Custom config loaded from: " + customPath);
            } catch (Exception e) {
                errorMsg = "Custom Config Failed: " + e.getMessage();
                api.logging().logToError(errorMsg);
            }
        }

        return new ConfigResult(config, errorMsg);
    }

    private RegisteredComponents registerComponents(MontoyaApi api, GitleaksConfiguration config,
            PluginSettings settings) {
        GitleaksScanCheck scanCheck = new GitleaksScanCheck(api, config, settings);
        api.scanner().registerPassiveScanCheck(scanCheck, ScanCheckType.PER_REQUEST);

        GitleaksContextMenuProvider menuProvider = new GitleaksContextMenuProvider(api, scanCheck, settings);
        api.userInterface().registerContextMenuItemsProvider(menuProvider);

        SettingsTab settingsTab = new SettingsTab(api, scanCheck, settings, config.rules());
        api.userInterface().registerSuiteTab(EXTENSION_TAB_NAME, settingsTab);

        return new RegisteredComponents(settingsTab, menuProvider);
    }

    private void handleStartupFeedback(MontoyaApi api, GitleaksConfiguration config, SettingsTab settingsTab,
            String startupError) {
        if (startupError != null) {
            Toast.error(settingsTab, startupError);
            api.logging().logToOutput("WARNING: Reverted to default rules due to configuration error.");
        } else {
            api.logging().logToOutput(EXTENSION_NAME + " ready. Active Rules: " + config.rules().size());
        }
    }
}