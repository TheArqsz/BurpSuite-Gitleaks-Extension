package com.arqsz.burpgitleaks.verification;

public class CurlGenerator {

    public static String toCurl(VerificationTemplate tmpl, String secret) {
        StringBuilder sb = new StringBuilder();

        sb.append("curl -i -s -k -X ").append(tmpl.method()).append(" ");

        if (tmpl.headers() != null) {
            tmpl.headers().forEach((k, v) -> {
                String val = v.replace("{{SECRET}}", secret);
                sb.append("-H \"").append(k).append(": ").append(val).append("\" ");
            });
        }

        if (tmpl.username() != null) {
            String user = tmpl.username().replace("{{SECRET}}", secret);
            String pass = tmpl.password() != null ? tmpl.password().replace("{{SECRET}}", secret) : "";
            sb.append("-u '").append(user).append(":").append(pass).append("' ");
        }

        if (tmpl.body() != null && !tmpl.body().isBlank()) {
            String body = tmpl.body().replace("{{SECRET}}", secret)
                    .replace("\n", "")
                    .replace("\"", "\\\"");
            sb.append("-d \"").append(body).append("\" ");
        }

        String finalUrl = tmpl.url().replace("{{SECRET}}", secret);
        sb.append("'").append(finalUrl).append("'");

        return sb.toString();
    }
}