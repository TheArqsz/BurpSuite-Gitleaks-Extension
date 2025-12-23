package com.arqsz.burpgitleaks.ui;

import java.time.LocalDateTime;
import java.util.Base64;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public class SavedIssue {
    public String name;
    public String detail;
    public String remediation;
    public String baseUrl;
    public String severity;
    public String confidence;
    public String overrideSeverity;
    public String overrideConfidence;
    public String requestBase64;
    public String responseBase64;
    public String timestamp;

    public SavedIssue() {
    }

    public SavedIssue(AuditIssue issue, LocalDateTime timestamp) {
        this.name = issue.name();
        this.detail = issue.detail();
        this.remediation = issue.remediation();
        this.baseUrl = issue.baseUrl();
        this.severity = issue.severity().name();
        this.confidence = issue.confidence().name();

        if (timestamp != null) {
            this.timestamp = timestamp.toString();
        }

        if (!issue.requestResponses().isEmpty()) {
            HttpRequestResponse rr = issue.requestResponses().get(0);
            if (rr.request() != null) {
                this.requestBase64 = Base64.getEncoder().encodeToString(rr.request().toByteArray().getBytes());
            }
            if (rr.response() != null) {
                this.responseBase64 = Base64.getEncoder().encodeToString(rr.response().toByteArray().getBytes());
            }
        }
    }

    public AuditIssue toAuditIssue(burp.api.montoya.MontoyaApi api) {
        HttpRequestResponse rr = null;
        if (requestBase64 != null) {
            byte[] reqBytes = Base64.getDecoder().decode(requestBase64);
            HttpRequest req = HttpRequest.httpRequest(ByteArray.byteArray(reqBytes));
            HttpResponse res = null;
            if (responseBase64 != null) {
                byte[] resBytes = Base64.getDecoder().decode(responseBase64);
                res = HttpResponse.httpResponse(ByteArray.byteArray(resBytes));
            }

            rr = HttpRequestResponse.httpRequestResponse(req, res);
        }

        return AuditIssue.auditIssue(
                name,
                detail,
                remediation,
                baseUrl,
                AuditIssueSeverity.valueOf(severity),
                AuditIssueConfidence.valueOf(confidence),
                null, null,
                AuditIssueSeverity.valueOf(severity),
                rr != null ? java.util.List.of(rr) : java.util.Collections.emptyList());
    }
}