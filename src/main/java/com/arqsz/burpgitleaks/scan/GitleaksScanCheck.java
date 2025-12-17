package com.arqsz.burpgitleaks.scan;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.ahocorasick.trie.Trie;

import com.arqsz.burpgitleaks.config.GitleaksAllowlist;
import com.arqsz.burpgitleaks.config.GitleaksRule;
import com.arqsz.burpgitleaks.config.PluginSettings;
import com.arqsz.burpgitleaks.config.RuleLoader.GitleaksConfiguration;
import com.arqsz.burpgitleaks.utils.Entropy;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;

public class GitleaksScanCheck implements PassiveScanCheck {

    private static final int MAX_SCAN_SIZE = 1024 * 1024 * 5;
    private static final int MAX_DECODE_DEPTH = 2;

    private static final String ISSUE_REMEDIATION = "Review the exposed file or secret and revoke it immediately. Ensure it is removed from the codebase and history.";
    private static final String ISSUE_BACKGROUND = "Hardcoded secrets (such as API keys, passwords, and tokens) in HTTP responses may allow unauthorized access to sensitive resources.";

    private static final Pattern BASE64_PATTERN = Pattern.compile("[a-zA-Z0-9+\\-_]{20,}={0,2}");

    private static final Set<MimeType> IGNORED_MIME_TYPES = Set.of(
            MimeType.IMAGE_UNKNOWN, MimeType.IMAGE_JPEG, MimeType.IMAGE_GIF,
            MimeType.IMAGE_PNG, MimeType.IMAGE_BMP, MimeType.IMAGE_TIFF,
            MimeType.FONT_WOFF, MimeType.FONT_WOFF2, MimeType.SOUND, MimeType.VIDEO);

    private volatile ScanState scanState;
    private final PluginSettings settings;
    private final Logging logging;

    private record ScanState(
            List<GitleaksRule> rules,
            List<GitleaksAllowlist> allowlists,
            Trie keywordTrie) {
    }

    public GitleaksScanCheck(MontoyaApi api, GitleaksConfiguration config, PluginSettings settings) {
        this.logging = api.logging();
        this.settings = settings;
        updateConfig(config);
    }

    public void updateConfig(GitleaksConfiguration config) {
        Trie newTrie = buildTrie(config.rules());

        this.scanState = new ScanState(config.rules(), config.globalAllowlists(), newTrie);
    }

    @Override
    public String checkName() {
        return "Gitleaks Passive Check";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        var response = baseRequestResponse.response();
        if (response == null)
            return AuditResult.auditResult(Collections.emptyList());

        if (response.body().length() > MAX_SCAN_SIZE || IGNORED_MIME_TYPES.contains(response.inferredMimeType())) {
            return AuditResult.auditResult(Collections.emptyList());
        }

        String body = response.bodyToString();
        if (body.isEmpty()) {
            return AuditResult.auditResult(Collections.emptyList());
        }

        List<AuditIssue> issues = new ArrayList<>();

        scanContent(body, issues, 0, baseRequestResponse, Collections.emptyList());

        return AuditResult.auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (existingIssue.name().equals(newIssue.name()) &&
                existingIssue.detail().equals(newIssue.detail()) &&
                existingIssue.baseUrl().equals(newIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    private void scanContent(String content, List<AuditIssue> issues, int depth, HttpRequestResponse baseReq,
            List<Marker> contextMarkers) {
        if (depth > MAX_DECODE_DEPTH)
            return;

        scanLayer(content, issues, baseReq, depth, contextMarkers);

        Matcher b64Matcher = BASE64_PATTERN.matcher(content);

        while (b64Matcher.find()) {
            String decoded = tryDecode(b64Matcher.group());

            if (decoded != null && isPrintable(decoded)) {
                List<Marker> nextMarkers = contextMarkers;

                if (depth == 0) {
                    int bodyOffset = baseReq.response().bodyOffset();
                    nextMarkers = List.of(Marker.marker(
                            bodyOffset + b64Matcher.start(),
                            bodyOffset + b64Matcher.end()));
                }

                scanContent(decoded, issues, depth + 1, baseReq, nextMarkers);
            }
        }
    }

    private void scanLayer(String body, List<AuditIssue> issues, HttpRequestResponse baseReq, int depth,
            List<Marker> contextMarkers) {

        ScanState state = this.scanState;
        String requestPath = baseReq.request().path();

        Set<String> foundKeywords = state.keywordTrie.parseText(body).stream()
                .map(emit -> emit.getKeyword().toLowerCase())
                .collect(Collectors.toSet());

        List<String> disabledRules = settings.getDisabledRules();
        boolean debugMode = settings.isDebugEnabled();

        java.util.function.Consumer<String> debugLogger = msg -> {
            if (debugMode)
                this.logging.logToOutput(msg);
        };

        List<GitleaksRule> currentRules = state.rules();

        for (GitleaksRule rule : currentRules) {
            if (disabledRules.contains(rule.getId()))
                continue;

            if (rule.getPathRegex() != null) {
                if (!rule.getPathRegex().matcher(requestPath).find()) {
                    logging.logToOutput(
                            "Applying path regex " + rule.getPathRegex() + " for path " + requestPath);
                    continue;
                }
            }

            if (rule.getRegex() == null) {
                if (depth == 0 && rule.getPathRegex() != null) {
                    handleFileOnlyRule(rule, requestPath, baseReq, issues, state.allowlists());
                }
                continue;
            }

            if (!rule.getKeywords().isEmpty() && !foundKeywords.isEmpty()) {
                if (rule.getKeywords().stream().noneMatch(foundKeywords::contains)) {
                    continue;
                }
            }

            scanRule(body, rule, issues, baseReq, depth, contextMarkers, state.allowlists(), requestPath, debugLogger);
        }
    }

    private void handleFileOnlyRule(GitleaksRule rule, String requestPath, HttpRequestResponse baseReq,
            List<AuditIssue> issues, List<GitleaksAllowlist> allowlists) {

        if (isAllowed(allowlists, requestPath, requestPath, "", requestPath, "Global")) {
            return;
        }

        issues.add(AuditIssue.auditIssue(
                "Secret leakage (sensitive file): " + rule.getId(),
                rule.getDescription() + "<br><br><b>Match (path detected by rule):</b><br><pre>"
                        + rule.getPathRegex().pattern() + "</pre>",
                ISSUE_REMEDIATION,
                baseReq.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.CERTAIN,
                rule.getDescription(),
                ISSUE_BACKGROUND,
                AuditIssueSeverity.HIGH,
                baseReq.withResponseMarkers(Collections.emptyList())));
    }

    private void scanRule(String body, GitleaksRule rule, List<AuditIssue> issues, HttpRequestResponse baseReq,
            int depth, List<Marker> contextMarkers, List<GitleaksAllowlist> globalAllowlists, String requestPath,
            Consumer<String> debugLogger) {

        Matcher matcher = rule.getRegex().matcher(body);
        while (matcher.find()) {
            handleMatch(body, matcher, rule, issues, baseReq, depth, contextMarkers, globalAllowlists, requestPath,
                    debugLogger);
        }
    }

    private void handleMatch(String body, Matcher matcher, GitleaksRule rule, List<AuditIssue> issues,
            HttpRequestResponse baseReq, int depth, List<Marker> contextMarkers,
            List<GitleaksAllowlist> globalAllowlists, String requestPath, Consumer<String> debugLogger) {

        String fullMatch = matcher.group(0);
        String secretCandidate = fullMatch;

        if (rule.getSecretGroup() > 0 && rule.getSecretGroup() <= matcher.groupCount()) {
            secretCandidate = matcher.group(rule.getSecretGroup());
        }

        if (rule.getMinEntropy() > 0 && Entropy.shannonEntropy(secretCandidate) < rule.getMinEntropy()) {
            if (settings.isDebugEnabled()) {
                logging.logToOutput("Ignored low entropy match for rule " + rule.getId() + ": " + secretCandidate);
            }
            return;
        }

        String lineContext = extractLine(body, matcher.start(), matcher.end());

        if (isAllowed(globalAllowlists, secretCandidate, fullMatch, lineContext, requestPath, "Global")) {
            return;
        }

        if (rule.isAllowed(secretCandidate, fullMatch, lineContext, requestPath, debugLogger)) {
            if (settings.isDebugEnabled()) {
                logging.logToOutput("[Rule: " + rule.getId() + "] Blocked by Rule Allowlist: " + secretCandidate);
            }
            return;
        }

        if (!settings.getIgnoreGitleaksAllow() && lineContext.contains("gitleaks:allow")) {
            if (settings.isDebugEnabled()) {
                logging.logToOutput("Ignored due to in-line gitleaks:allow comment: " + secretCandidate);
            }
            return;
        }

        issues.add(createAuditIssue(rule, secretCandidate, fullMatch, matcher, baseReq, depth, contextMarkers));
    }

    private AuditIssue createAuditIssue(GitleaksRule rule, String secret, String fullMatch, Matcher matcher,
            HttpRequestResponse baseReq, int depth, List<Marker> contextMarkers) {

        String redacted = applyRedaction(fullMatch, settings.getRedactionLevel());
        String displayMatch = escapeHtml(redacted);

        String description = rule.getDescription() + "<br><br><b>Match:</b><br><pre>" + displayMatch + "</pre>";

        if (depth > 0) {
            description = rule.getDescription() + "<br><br><b>Match found in Base64 decoded layer (Depth "
                    + depth + "):</b><br><pre>" + displayMatch + "</pre>";
        }

        List<Marker> markers;
        if (depth == 0) {
            int groupIndex = (rule.getSecretGroup() > 0 && rule.getSecretGroup() <= matcher.groupCount())
                    ? rule.getSecretGroup()
                    : 0;

            int bodyOffset = baseReq.response().bodyOffset();
            markers = List.of(Marker.marker(
                    bodyOffset + matcher.start(groupIndex),
                    bodyOffset + matcher.end(groupIndex)));
        } else {
            markers = contextMarkers;
        }

        return AuditIssue.auditIssue(
                "Secret leakage: " + rule.getId(),
                description,
                ISSUE_REMEDIATION,
                baseReq.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                rule.getDescription(),
                ISSUE_BACKGROUND,
                AuditIssueSeverity.HIGH,
                baseReq.withResponseMarkers(markers));
    }

    private boolean isAllowed(List<GitleaksAllowlist> allowlists, String secret, String fullMatch, String line,
            String filePath, String contextName) {
        if (allowlists == null || allowlists.isEmpty())
            return false;
        for (GitleaksAllowlist allowlist : allowlists) {
            if (allowlist.isAllowed(secret, fullMatch, line, filePath)) {
                if (settings.isDebugEnabled()) {
                    logging.logToOutput(String.format("[%s Allowlist] IGNORED secret '%s' due to allowlist: %s",
                            contextName, secret, allowlist.toString()));
                }
                return true;
            }
        }
        return false;
    }

    private String applyRedaction(String secret, int level) {
        if (level <= 0)
            return secret;
        if (level >= 100)
            return "REDACTED";

        int len = secret.length();
        int redactCount = (int) Math.ceil(len * (level / 100.0));
        if (redactCount >= len)
            return "REDACTED";

        int visibleCount = len - redactCount;
        int prefixLen = (int) Math.ceil(visibleCount / 2.0);
        int suffixLen = visibleCount - prefixLen;

        return secret.substring(0, prefixLen) +
                "*".repeat(redactCount) +
                secret.substring(len - suffixLen);
    }

    private String escapeHtml(String input) {
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\\n", "\n")
                .replace("\\\\n", "\n");
    }

    private String tryDecode(String s) {
        try {
            byte[] bytes = (s.contains("-") || s.contains("_"))
                    ? java.util.Base64.getUrlDecoder().decode(s)
                    : java.util.Base64.getDecoder().decode(s);
            return new String(bytes);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private boolean isPrintable(String s) {
        if (s.isEmpty())
            return false;
        long controlChars = s.chars()
                .filter(c -> (c < 32 && c != '\n' && c != '\r' && c != '\t') || c > 126)
                .count();
        return (double) controlChars / s.length() < 0.3;
    }

    private String extractLine(String body, int start, int end) {
        int lineStart = body.lastIndexOf('\n', start);
        if (lineStart == -1)
            lineStart = 0;
        else
            lineStart++;

        int lineEnd = body.indexOf('\n', end);
        if (lineEnd == -1)
            lineEnd = body.length();

        return body.substring(lineStart, lineEnd);
    }

    private Trie buildTrie(List<GitleaksRule> rules) {
        Trie.TrieBuilder builder = Trie.builder().ignoreCase();
        for (GitleaksRule rule : rules) {
            for (String kw : rule.getKeywords()) {
                builder.addKeyword(kw);
            }
        }
        return builder.build();
    }
}