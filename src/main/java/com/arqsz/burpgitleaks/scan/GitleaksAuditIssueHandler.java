package com.arqsz.burpgitleaks.scan;

import com.arqsz.burpgitleaks.config.PluginSettings;
import com.arqsz.burpgitleaks.ui.IssuesTab;

import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

public class GitleaksAuditIssueHandler implements AuditIssueHandler {

    private final IssuesTab issuesTab;
    private final PluginSettings settings;

    public GitleaksAuditIssueHandler(IssuesTab issuesTab, PluginSettings settings) {
        this.issuesTab = issuesTab;
        this.settings = settings;
    }

    @Override
    public void handleNewAuditIssue(AuditIssue auditIssue) {
        if (!settings.isShowIssuesTab()) {
            return;
        }

        if (auditIssue.name().startsWith("Secret leakage")) {
            issuesTab.addIssue(auditIssue);
        }
    }
}