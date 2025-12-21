package com.arqsz.burpgitleaks.verification;

import java.util.Map;

public record VerificationTemplate(
        String name,
        String type,
        String method,
        String url,
        String body,
        String username,
        String password,
        String command,
        Map<String, String> headers) {
}