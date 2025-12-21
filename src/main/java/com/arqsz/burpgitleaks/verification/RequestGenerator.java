package com.arqsz.burpgitleaks.verification;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import burp.api.montoya.http.message.requests.HttpRequest;

public class RequestGenerator {

    public static HttpRequest build(VerificationTemplate tmpl, String secret) {
        String finalUrl = tmpl.url().replace("{{SECRET}}", secret);

        HttpRequest request = HttpRequest.httpRequestFromUrl(finalUrl)
                .withMethod(tmpl.method());

        if (tmpl.headers() != null) {
            for (var entry : tmpl.headers().entrySet()) {
                String val = entry.getValue().replace("{{SECRET}}", secret);
                request = request.withHeader(entry.getKey(), val);
            }
        }

        if (tmpl.username() != null) {
            String user = tmpl.username().replace("{{SECRET}}", secret);
            String pass = tmpl.password() != null ? tmpl.password().replace("{{SECRET}}", secret) : "";

            String authString = user + ":" + pass;
            String encoded = Base64.getEncoder().encodeToString(authString.getBytes(StandardCharsets.UTF_8));

            request = request.withHeader("Authorization", "Basic " + encoded);
        }

        if (tmpl.body() != null && !tmpl.body().isBlank()) {
            String body = tmpl.body().replace("{{SECRET}}", secret);
            request = request.withBody(body);
        }

        return request;
    }
}