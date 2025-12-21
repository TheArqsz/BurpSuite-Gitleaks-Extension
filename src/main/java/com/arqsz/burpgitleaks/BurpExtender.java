package com.arqsz.burpgitleaks;

import java.util.List;

import javax.swing.SwingUtilities;

import com.arqsz.burpgitleaks.config.PluginSettings;
import com.arqsz.burpgitleaks.config.RuleLoader;
import com.arqsz.burpgitleaks.config.RuleLoader.GitleaksConfiguration;
import com.arqsz.burpgitleaks.scan.GitleaksAuditIssueHandler;
import com.arqsz.burpgitleaks.scan.GitleaksHttpHandler;
import com.arqsz.burpgitleaks.scan.GitleaksScanCheck;
import com.arqsz.burpgitleaks.ui.GitleaksContextMenuProvider;
import com.arqsz.burpgitleaks.ui.IssuesTab;
import com.arqsz.burpgitleaks.ui.SettingsTab;
import com.arqsz.burpgitleaks.ui.Toast;
import com.arqsz.burpgitleaks.verification.TemplateManager;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Registration;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

public class BurpExtender implements BurpExtension {

    private final String EXTENSION_NAME = "Gitleaks Integration";
    private final String EXTENSION_TAB_NAME = EXTENSION_NAME + " Settings";
    private final String ISSUES_TAB_NAME = EXTENSION_NAME + " Issues";

    private MontoyaApi api;
    private IssuesTab issuesTab;
    private Registration issuesTabRegistration;
    private TemplateManager templateManager;

    private GitleaksHttpHandler communityHttpHandler;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(EXTENSION_NAME);

        PluginSettings settings = new PluginSettings(api.persistence().preferences());

        ConfigResult configResult = loadInitialConfiguration(api, settings);
        GitleaksConfiguration config = configResult.config;

        TemplateManager templateManager = new TemplateManager(api.logging());

        var components = registerComponents(api, config, settings, templateManager);

        handleStartupFeedback(api, config, configResult.errorMsg());

        api.extension().registerUnloadingHandler(() -> {
            components.settingsTab().shutdown();
            components.menuProvider().shutdown();

            if (communityHttpHandler != null) {
                communityHttpHandler.shutdown();
            }

            deregisterIssuesTab();
        });

    }

    private record ConfigResult(GitleaksConfiguration config, String errorMsg) {
    }

    private record RegisteredComponents(SettingsTab settingsTab, GitleaksContextMenuProvider menuProvider,
            IssuesTab issuesTab) {
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
            PluginSettings settings, TemplateManager templateManager) {
        this.issuesTab = new IssuesTab(api, ISSUES_TAB_NAME, templateManager);

        if (settings.isShowIssuesTab()) {
            registerIssuesTab();
        }

        GitleaksScanCheck scanCheck = new GitleaksScanCheck(api, config, settings);

        BurpSuiteEdition edition = api.burpSuite().version().edition();

        if (edition == BurpSuiteEdition.COMMUNITY_EDITION) {
            api.logging().logToOutput("Community Edition detected: Activating manual traffic handler.");
            this.communityHttpHandler = new GitleaksHttpHandler(api, scanCheck, settings, issuesTab);
            api.http().registerHttpHandler(communityHttpHandler);
        } else {
            api.scanner().registerPassiveScanCheck(scanCheck, ScanCheckType.PER_REQUEST);
            GitleaksAuditIssueHandler auditHandler = new GitleaksAuditIssueHandler(issuesTab, settings);
            api.scanner().registerAuditIssueHandler(auditHandler);
        }

        GitleaksContextMenuProvider menuProvider = new GitleaksContextMenuProvider(api, scanCheck, settings,
                templateManager, issuesTab);
        api.userInterface().registerContextMenuItemsProvider(menuProvider);

        SettingsTab settingsTab = new SettingsTab(api, scanCheck, settings, config.rules(), (visible) -> {
            if (visible)
                registerIssuesTab();
            else
                deregisterIssuesTab();
        });
        api.userInterface().registerSuiteTab(EXTENSION_TAB_NAME, settingsTab);

        return new RegisteredComponents(settingsTab, menuProvider, issuesTab);
    }

    private void registerIssuesTab() {
        if (issuesTabRegistration == null && issuesTab != null) {
            issuesTabRegistration = api.userInterface().registerSuiteTab(ISSUES_TAB_NAME, issuesTab);
        }
    }

    private void deregisterIssuesTab() {
        if (issuesTabRegistration != null) {
            issuesTabRegistration.deregister();
            issuesTabRegistration = null;
        }
    }

    private void handleStartupFeedback(MontoyaApi api, GitleaksConfiguration config,
            String startupError) {
        if (startupError != null) {
            api.logging().logToError("Startup configuration error: " + startupError);
            api.logging().logToOutput("WARNING: Reverted to default rules due to configuration error.");
            SwingUtilities.invokeLater(() -> {
                java.awt.Window suiteFrame = api.userInterface().swingUtils().suiteFrame();
                Toast.error(suiteFrame, EXTENSION_NAME + "startup failed: Reverted to defaults");
            });
        } else {
            api.logging().logToOutput(String.format("%s (by Arqsz) initialized successfully.", EXTENSION_NAME));
            api.logging().logToOutput(String.format("Loaded %d active rules.", config.rules().size()));
        }
    }
}