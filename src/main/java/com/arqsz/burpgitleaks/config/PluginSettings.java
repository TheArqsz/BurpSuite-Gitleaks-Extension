package com.arqsz.burpgitleaks.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.api.montoya.persistence.Preferences;

public class PluginSettings {
    private static final String KEY_URL = "gitleaks_config_url";
    private static final String KEY_CUSTOM_PATH = "gitleaks_custom_path";
    private static final String KEY_DISABLED_RULES = "gitleaks_disabled_rules";
    private static final String KEY_REDACT_LEVEL = "gitleaks_redact_level";
    private static final String KEY_IGNORE_ALLOW = "gitleaks_ignore_allow";
    private static final String KEY_DEBUG_LOGGING = "gitleaks_debug_logging";

    private final Preferences prefs;

    public PluginSettings(Preferences prefs) {
        this.prefs = prefs;
    }

    public String getUrl() {
        String url = prefs.getString(KEY_URL);
        return (url == null || url.isBlank()) ? RuleLoader.OFFICIAL_URL : url;
    }

    public void setUrl(String url) {
        prefs.setString(KEY_URL, url);
    }

    public String getCustomPath() {
        return prefs.getString(KEY_CUSTOM_PATH);
    }

    public void setCustomPath(String path) {
        prefs.setString(KEY_CUSTOM_PATH, path);
    }

    public List<String> getDisabledRules() {
        String raw = prefs.getString(KEY_DISABLED_RULES);
        if (raw == null || raw.isBlank()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(Arrays.asList(raw.split(",")));
    }

    public void setDisabledRules(List<String> rules) {
        if (rules == null || rules.isEmpty()) {
            prefs.deleteString(KEY_DISABLED_RULES);
            return;
        }
        if (rules.stream().anyMatch(id -> id.contains(","))) {
            throw new IllegalArgumentException("Rule IDs cannot contain commas");
        }
        prefs.setString(KEY_DISABLED_RULES, String.join(",", rules));
    }

    public int getRedactionLevel() {
        Integer level = prefs.getInteger(KEY_REDACT_LEVEL);
        return level == null ? 70 : level;
    }

    public void setRedactionLevel(int level) {
        prefs.setInteger(KEY_REDACT_LEVEL, level);
    }

    public boolean getIgnoreGitleaksAllow() {
        return Boolean.TRUE.equals(prefs.getBoolean(KEY_IGNORE_ALLOW));
    }

    public void setIgnoreGitleaksAllow(boolean ignore) {
        prefs.setBoolean(KEY_IGNORE_ALLOW, ignore);
    }

    public boolean isDebugEnabled() {
        return Boolean.TRUE.equals(prefs.getBoolean(KEY_DEBUG_LOGGING));
    }

    public void setDebugEnabled(boolean debug) {
        prefs.setBoolean(KEY_DEBUG_LOGGING, debug);
    }
}