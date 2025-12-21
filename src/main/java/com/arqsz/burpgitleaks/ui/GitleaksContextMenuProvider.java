package com.arqsz.burpgitleaks.ui;

import java.awt.Component;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import com.arqsz.burpgitleaks.config.PluginSettings;
import com.arqsz.burpgitleaks.scan.GitleaksScanCheck;
import com.arqsz.burpgitleaks.verification.CurlGenerator;
import com.arqsz.burpgitleaks.verification.RequestGenerator;
import com.arqsz.burpgitleaks.verification.TemplateManager;
import com.arqsz.burpgitleaks.verification.VerificationTemplate;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
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
    private final TemplateManager templateManager;

    public GitleaksContextMenuProvider(MontoyaApi api, GitleaksScanCheck scanCheck,
            PluginSettings settings) {
        this.api = api;
        this.scanCheck = scanCheck;
        this.settings = settings;
        this.executor = Executors.newSingleThreadExecutor();
        this.templateManager = new TemplateManager(api.logging());
    }

    @Override
    public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
        if (event.selectedIssues().isEmpty()) {
            return Collections.emptyList();
        }

        List<Component> menuItems = new ArrayList<>();
        AuditIssue issue = event.selectedIssues().get(0);
        String ruleId = extractRuleId(issue);

        if (ruleId != null && templateManager.hasTemplate(ruleId)) {
            List<Component> verificationMenuItems = createVerificationMenuItems(issue, ruleId);
            menuItems.addAll(verificationMenuItems);
        }

        return menuItems;
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

    private List<Component> createVerificationMenuItems(AuditIssue issue, String ruleId) {
        List<Component> items = new ArrayList<>();
        VerificationTemplate tmpl = templateManager.getTemplate(ruleId);
        String secret = extractSecret(issue);

        if (secret == null || secret.isBlank())
            return Collections.emptyList();

        if ("http".equalsIgnoreCase(tmpl.type())) {
            JMenuItem repeaterItem = new JMenuItem("Verify: send query to Repeater");
            repeaterItem.addActionListener(e -> {
                HttpRequest req = RequestGenerator.build(tmpl, secret);
                api.repeater().sendToRepeater(req, "Verify secret: " + ruleId);
                Toast.success(api.userInterface().swingUtils().suiteFrame(), "Request sent to Repeater");
            });
            items.add(repeaterItem);

            JMenuItem curlItem = new JMenuItem("Verify: copy as cURL");
            curlItem.addActionListener(e -> {
                String cmd = CurlGenerator.toCurl(tmpl, secret);
                copyToClipboard(cmd);
                Toast.success(api.userInterface().swingUtils().suiteFrame(), "cURL copied to clipboard");
            });
            items.add(curlItem);
        } else if ("cli".equalsIgnoreCase(tmpl.type())) {
            JMenuItem cliItem = new JMenuItem("Verify: copy verification command");
            cliItem.addActionListener(e -> {
                String cmd = tmpl.command().replace("{{SECRET}}", secret);
                copyToClipboard(cmd);
                Toast.success(api.userInterface().swingUtils().suiteFrame(), "Command copied to clipboard");
            });
            items.add(cliItem);
        } else if ("guide".equalsIgnoreCase(tmpl.type())) {
            JMenuItem guideItem = new JMenuItem("Verify: show verification steps");
            guideItem.addActionListener(e -> {
                String text = tmpl.body().replace("{{SECRET}}", secret);
                showInstructionDialog(tmpl.name(), text);
            });
            items.add(guideItem);
        }

        return items;
    }

    private String extractRuleId(AuditIssue issue) {
        if (issue.name().startsWith("Secret leakage: ")) {
            return issue.name().substring(16).trim();
        }
        return null;
    }

    private String extractSecret(AuditIssue issue) {
        String detail = issue.detail();
        if (detail != null) {
            Matcher m = Pattern.compile("<pre>(.*?)</pre>").matcher(detail);
            if (m.find()) {
                String match = m.group(1).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">");
                if (!match.contains("*") && !match.equals("REDACTED")) {
                    return match;
                }
            }
        }

        if (!issue.requestResponses().isEmpty()) {
            var reqRes = issue.requestResponses().get(0);
            String fullResponse = reqRes.response().toString();

            if (!reqRes.responseMarkers().isEmpty()) {
                var marker = reqRes.responseMarkers().get(0);

                if (marker.range().startIndexInclusive() >= 0
                        && marker.range().endIndexExclusive() <= fullResponse.length()) {
                    return fullResponse.substring(marker.range().startIndexInclusive(),
                            marker.range().endIndexExclusive());
                }
            }
        }
        return null;
    }

    private void showInstructionDialog(String title, String content) {
        SwingUtilities.invokeLater(() -> {
            JTextArea textArea = new JTextArea(content);
            textArea.setEditable(false);
            textArea.setWrapStyleWord(true);
            textArea.setLineWrap(true);
            textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

            JScrollPane scrollPane = new JScrollPane(textArea);
            scrollPane.setPreferredSize(new java.awt.Dimension(500, 300));

            JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    scrollPane,
                    "Verification: " + title,
                    JOptionPane.INFORMATION_MESSAGE);
        });
    }

    private void copyToClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
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
                if (isAlreadyReported(newIssue)) {
                    duplicatesIgnored++;
                    if (settings.isDebugEnabled()) {
                        api.logging().logToOutput("Ignored duplicate: " + newIssue.name() + " @ " + newIssue.baseUrl());
                    }
                    continue;
                }

                api.siteMap().add(newIssue);
                issuesFound++;
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
        List<AuditIssue> existingIssues = api.siteMap().issues(
                SiteMapFilter.prefixFilter(newIssue.baseUrl()));

        return existingIssues.stream()
                .anyMatch(existing -> existing.baseUrl().toString().equals(newIssue.baseUrl().toString()) &&
                        existing.name().equals(newIssue.name()) &&
                        existing.detail().equals(newIssue.detail()));
    }
}