package com.arqsz.burpgitleaks.utils;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

public class IssueUtils {
    private static final Pattern SECRET_PATTERN = Pattern.compile("<pre>(.*?)</pre>");
    private static final String ISSUE_PREFIX = "Secret leakage: ";

    public static String extractRuleId(AuditIssue issue) {
        if (issue.name().startsWith(ISSUE_PREFIX)) {
            return issue.name().substring(ISSUE_PREFIX.length()).trim();
        }
        return null;
    }

    public static String extractSecret(AuditIssue issue) {
        String detail = issue.detail();
        if (detail != null) {
            Matcher m = SECRET_PATTERN.matcher(detail);
            if (m.find()) {
                String match = m.group(1)
                        .replace("&amp;", "&")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">");

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
}