package com.arqsz.burpgitleaks.scan;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.arqsz.burpgitleaks.config.PluginSettings;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

public class GitleaksHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final GitleaksScanCheck scanCheck;
    private final PluginSettings settings;
    private final ExecutorService executor;

    public GitleaksHttpHandler(MontoyaApi api, GitleaksScanCheck scanCheck, PluginSettings settings) {
        this.api = api;
        this.scanCheck = scanCheck;
        this.settings = settings;
        this.executor = Executors.newFixedThreadPool(3);
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!isToolEnabled(responseReceived.toolSource().toolType())) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        HttpRequestResponse reqRes = HttpRequestResponse.httpRequestResponse(
                responseReceived.initiatingRequest(),
                responseReceived);

        executor.submit(() -> runScan(reqRes));

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void runScan(HttpRequestResponse reqRes) {
        AuditResult result = scanCheck.doCheck(reqRes);

        for (AuditIssue issue : result.auditIssues()) {
            api.siteMap().add(issue);
        }
    }

    private boolean isToolEnabled(ToolType toolType) {
        return toolType == ToolType.PROXY || toolType == ToolType.REPEATER;
    }
}