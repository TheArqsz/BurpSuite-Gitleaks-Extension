package com.arqsz.burpgitleaks.ui;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

import com.arqsz.burpgitleaks.config.PluginSettings;
import com.arqsz.burpgitleaks.scan.GitleaksScanCheck;
import com.arqsz.burpgitleaks.utils.IssueUtils;
import com.arqsz.burpgitleaks.verification.TemplateManager;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

public class GitleaksContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final GitleaksScanCheck scanCheck;
    private final ExecutorService executor;
    private final PluginSettings settings;
    private final VerificationMenuFactory menuFactory;
    private final IssuesTab issuesTab;

    public GitleaksContextMenuProvider(MontoyaApi api, GitleaksScanCheck scanCheck,
            PluginSettings settings, TemplateManager templateManager, IssuesTab issuesTab) {
        this.api = api;
        this.scanCheck = scanCheck;
        this.settings = settings;
        this.issuesTab = issuesTab;
        this.executor = Executors.newSingleThreadExecutor();
        this.menuFactory = new VerificationMenuFactory(api, templateManager);
    }

    @Override
    public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
        if (event.selectedIssues().isEmpty()) {
            return Collections.emptyList();
        }

        if (event.selectedIssues().size() == 1) {
            AuditIssue issue = event.selectedIssues().get(0);

            String ruleId = IssueUtils.extractRuleId(issue);
            String secret = IssueUtils.extractSecret(issue);

            return new ArrayList<>(menuFactory.createMenuItems(ruleId, secret));
        }

        return Collections.emptyList();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.selectedRequestResponses().isEmpty()) {
            return Collections.emptyList();
        }

        JMenuItem rescanItem = new JMenuItem("Force Rescan");
        rescanItem.addActionListener(e -> {
            List<HttpRequestResponse> itemsToScan = new ArrayList<>(event.selectedRequestResponses());

            Component suiteFrame = api.userInterface().swingUtils().suiteFrame();
            Toast.info(suiteFrame, "Scanning " + itemsToScan.size() + " item[s]...");

            executor.submit(() -> performManualScan(itemsToScan));
        });

        return List.of(rescanItem);
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    private void performManualScan(List<HttpRequestResponse> items) {
        int issuesFound = 0;
        int duplicatesIgnored = 0;

        if (settings.isDebugEnabled()) {
            api.logging().logToOutput("Starting manual secret scan on " + items.size() + " items...");
        }

        for (HttpRequestResponse item : items) {
            AuditResult result;
            try {
                result = scanCheck.doCheck(item);
            } catch (Exception e) {
                api.logging().logToError("Error during manual secret scan: " + e.getMessage());
                continue;
            }

            for (AuditIssue newIssue : result.auditIssues()) {
                boolean addedToTab = false;
                if (settings.isShowIssuesTab()) {
                    addedToTab = issuesTab.addIssue(newIssue);
                }

                boolean alreadyInSiteMap = isAlreadyReported(newIssue);

                if (!alreadyInSiteMap) {
                    api.siteMap().add(newIssue);
                }

                if (!alreadyInSiteMap || addedToTab) {
                    issuesFound++;
                } else {
                    duplicatesIgnored++;
                    if (settings.isDebugEnabled()) {
                        api.logging().logToOutput("Ignored duplicate: " + newIssue.name() + " @ " + newIssue.baseUrl());
                    }
                }
            }
        }

        handleScanCompletion(issuesFound, duplicatesIgnored);
    }

    private void handleScanCompletion(int issuesFound, int duplicatesIgnored) {
        String msg = buildResultToastMessage(issuesFound, duplicatesIgnored);

        if (settings.isDebugEnabled()) {
            api.logging().logToOutput(msg);
        }

        SwingUtilities.invokeLater(() -> {
            Component mainFrame = api.userInterface().swingUtils().suiteFrame();
            if (issuesFound > 0) {
                Toast.success(mainFrame, msg);
            } else {
                Toast.info(mainFrame, msg);
            }
        });
    }

    private String buildResultToastMessage(int issuesFound, int duplicatesIgnored) {
        if (issuesFound > 0) {
            String suffix = (duplicatesIgnored > 0)
                    ? String.format(" (ignored %d potential duplicate%s).", duplicatesIgnored,
                            duplicatesIgnored == 1 ? "" : "s")
                    : ".";
            return String.format("Manual scan complete. Added %d new issue%s%s",
                    issuesFound, issuesFound == 1 ? "" : "s", suffix);
        }

        if (duplicatesIgnored > 0) {
            return String.format("Manual scan complete. No new issues. Ignored %d duplicate%s.",
                    duplicatesIgnored, duplicatesIgnored == 1 ? "" : "s");
        }

        return "Manual scan complete. No secrets found.";
    }

    private boolean isAlreadyReported(AuditIssue newIssue) {
        if (api.burpSuite().version().edition() == BurpSuiteEdition.COMMUNITY_EDITION) {
            return true;
        }

        List<AuditIssue> existingIssues = api.siteMap().issues(
                SiteMapFilter.prefixFilter(newIssue.baseUrl()));

        return existingIssues.stream()
                .anyMatch(existing -> existing.baseUrl().toString().equals(newIssue.baseUrl().toString()) &&
                        existing.name().equals(newIssue.name()) &&
                        existing.detail().equals(newIssue.detail()));
    }
}