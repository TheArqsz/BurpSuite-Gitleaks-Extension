package com.arqsz.burpgitleaks.config;

import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

import com.google.re2j.Pattern;

public class GitleaksAllowlist {
    private final String description;
    private final List<Pattern> regexes;
    private final List<Pattern> paths;
    private final List<String> stopWords;
    private final boolean matchAll;
    private final String regexTarget;

    public GitleaksAllowlist(String description, List<Pattern> regexes, List<Pattern> paths,
            List<String> stopWords, boolean matchAll, String regexTarget) {
        this.description = description;
        this.regexes = regexes != null ? regexes : Collections.emptyList();
        this.paths = paths != null ? paths : Collections.emptyList();
        this.stopWords = stopWords != null ? stopWords : Collections.emptyList();
        this.matchAll = matchAll;
        this.regexTarget = regexTarget;
    }

    public boolean isAllowed(String secret, String fullMatch, String line, String filePath, Consumer<String> logger) {
        String target = determineTarget(secret, fullMatch, line);

        boolean regexMatch = checkRegexes(target, logger);
        boolean pathMatch = checkPaths(filePath, logger);
        boolean stopWordMatch = checkStopWords(secret, logger);

        boolean result;
        if (matchAll) {
            result = true;
            if (!regexes.isEmpty())
                result &= regexMatch;
            if (!paths.isEmpty())
                result &= pathMatch;
            if (!stopWords.isEmpty())
                result &= stopWordMatch;
        } else {
            result = regexMatch || pathMatch || stopWordMatch;
        }

        return result;
    }

    public boolean isAllowed(String secret, String fullMatch, String line, String filePath) {
        return isAllowed(secret, fullMatch, line, filePath, null);
    }

    private String determineTarget(String secret, String fullMatch, String line) {
        if ("match".equalsIgnoreCase(regexTarget))
            return fullMatch;
        if ("line".equalsIgnoreCase(regexTarget))
            return line;
        return secret;
    }

    private boolean checkRegexes(String target, Consumer<String> logger) {
        if (regexes.isEmpty())
            return false;

        for (Pattern p : regexes) {
            if (p.matcher(target).find()) {
                return true;
            }
        }

        return false;
    }

    private boolean checkPaths(String path, Consumer<String> logger) {
        if (paths.isEmpty() || path == null)
            return false;

        for (Pattern p : paths) {
            if (p.matcher(path).find()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkStopWords(String secret, Consumer<String> logger) {
        if (stopWords.isEmpty())
            return false;

        for (String word : stopWords) {
            if (secret.contains(word)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return String.format("\n\tAllowlist '%s'\n" +
                "  - MatchAll: %s\n" +
                "  - Target: %s\n" +
                "  - StopWords (%d): %s\n" +
                "  - Regexes (%d): %s\n" +
                "  - Paths (%d): %s",
                description, matchAll, regexTarget,
                stopWords.size(), stopWords,
                regexes.size(), regexes,
                paths.size(), paths);
    }
}