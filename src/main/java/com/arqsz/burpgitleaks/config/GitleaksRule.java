package com.arqsz.burpgitleaks.config;

import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;

public class GitleaksRule {
    private final String id;
    private final String description;
    private final String source;
    private final double minEntropy;
    private final int secretGroup;
    private final Pattern regex;
    private final Pattern pathRegex;
    private final List<String> keywords;
    private final List<GitleaksAllowlist> allowlists;

    public GitleaksRule(String id, String description, String source, double minEntropy, int secretGroup,
            String regexString, String pathRegexString, List<String> keywords, List<GitleaksAllowlist> allowlists) {
        this.id = id;
        this.description = description;
        this.source = source;
        this.minEntropy = minEntropy;
        this.secretGroup = secretGroup;
        this.allowlists = allowlists != null ? allowlists : Collections.emptyList();

        this.regex = compileSafe(regexString);
        this.pathRegex = compileSafe(pathRegexString);
        this.keywords = keywords != null ? keywords : Collections.emptyList();
    }

    public boolean isAllowed(String secret, String fullMatch, String line, String filePath, Consumer<String> logger) {
        for (GitleaksAllowlist allowlist : allowlists) {
            if (allowlist.isAllowed(secret, fullMatch, line, filePath, logger)) {
                return true;
            }
        }
        return false;
    }

    public boolean isAllowed(String secret, String fullMatch, String line, String filePath) {
        return isAllowed(secret, fullMatch, line, filePath, null);
    }

    public String getId() {
        return id;
    }

    public String getDescription() {
        return description;
    }

    public String getSource() {
        return source;
    }

    public double getMinEntropy() {
        return minEntropy;
    }

    public int getSecretGroup() {
        return secretGroup;
    }

    public Pattern getRegex() {
        return regex;
    }

    public Pattern getPathRegex() {
        return pathRegex;
    }

    public List<String> getKeywords() {
        return keywords;
    }

    private Pattern compileSafe(String regex) {
        if (regex == null || regex.isBlank())
            return null;

        try {
            return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid Regex: " + e.getMessage() + " in pattern: " + regex, e);
        }
    }
}