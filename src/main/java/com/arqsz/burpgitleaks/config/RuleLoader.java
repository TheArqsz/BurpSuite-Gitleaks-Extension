package com.arqsz.burpgitleaks.config;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.tomlj.Toml;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;
import org.tomlj.TomlTable;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;

public class RuleLoader {

    public static final String OFFICIAL_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml";
    public static final Path LOCAL_CONFIG_PATH = Path.of(System.getProperty("user.home"), ".burp-gitleaks",
            "gitleaks.toml");

    public record GitleaksConfiguration(List<GitleaksRule> rules, List<GitleaksAllowlist> globalAllowlists) {
    }

    public static GitleaksConfiguration loadConfiguration(String customConfigPath, Logging logging,
            boolean isDebugEnabled) throws IOException {
        GitleaksConfiguration baseConfig = loadBaseConfiguration(logging);
        GitleaksConfiguration finalConfig = baseConfig;

        if (customConfigPath != null && !customConfigPath.trim().isBlank()) {
            Path customPath = Path.of(customConfigPath.trim());
            if (Files.isRegularFile(customPath)) {
                try (InputStream is = Files.newInputStream(customPath)) {
                    GitleaksConfiguration customConfig = parseConfiguration(is, "Custom Config", logging);
                    finalConfig = mergeConfigurations(baseConfig, customConfig, logging, isDebugEnabled);
                }
            } else {
                throw new FileNotFoundException("Custom config file not found: " + customPath);
            }
        }

        if (isDebugEnabled) {
            logging.logToOutput("=== Active Allowlist Configuration ===");
            for (GitleaksAllowlist allowlist : finalConfig.globalAllowlists()) {
                logging.logToOutput(allowlist.toString());
            }
            logging.logToOutput("======================================");
        }

        return finalConfig;
    }

    public static String updateRules(MontoyaApi api, String targetUrl) throws Exception {
        if (targetUrl == null || targetUrl.isBlank())
            throw new IllegalArgumentException("Update URL cannot be empty");

        var responseObj = api.http().sendRequest(HttpRequest.httpRequestFromUrl(targetUrl));
        var response = responseObj.response();

        if (response.statusCode() != 200) {
            throw new IOException("Remote server returned status: " + response.statusCode());
        }

        String tomlContent = response.bodyToString();
        TomlParseResult result = Toml.parse(tomlContent);

        if (result.hasErrors()) {
            throw new IOException("Invalid TOML: " + result.errors().get(0).toString());
        }

        if (result.getArray("rules") == null || result.getArray("rules").isEmpty()) {
            throw new IOException("Downloaded TOML contains no rules.");
        }

        Files.createDirectories(LOCAL_CONFIG_PATH.getParent());
        Files.writeString(LOCAL_CONFIG_PATH, tomlContent);

        return "Updated successfully! Loaded " + result.getArray("rules").size() + " rules.";
    }

    public static void deleteLocalConfig() throws IOException {
        Files.deleteIfExists(LOCAL_CONFIG_PATH);
    }

    private static GitleaksConfiguration loadBaseConfiguration(Logging logging) {
        if (Files.exists(LOCAL_CONFIG_PATH)) {
            try (InputStream is = Files.newInputStream(LOCAL_CONFIG_PATH)) {
                return parseConfiguration(is, "Local File (" + LOCAL_CONFIG_PATH + ")", logging);
            } catch (IOException e) {
                logging.logToError("Failed to load local config, falling back to bundled: " + e.getMessage());
            }
        }

        try (InputStream is = RuleLoader.class.getResourceAsStream("/gitleaks.toml")) {
            if (is == null)
                throw new IOException("Bundled gitleaks.toml not found");
            return parseConfiguration(is, "Bundled Resource", logging);
        } catch (IOException e) {
            throw new RuntimeException("Critical failure: Could not load any rules.", e);
        }
    }

    private static GitleaksConfiguration parseConfiguration(InputStream is, String sourceName, Logging logging)
            throws IOException {
        TomlParseResult result = Toml.parse(is);
        if (result.hasErrors()) {
            throw new IOException("TOML Syntax Error in " + sourceName + ": " + result.errors().get(0).toString());
        }

        List<GitleaksAllowlist> globalAllowlists = new ArrayList<>();

        if (result.contains("allowlist")) {
            if (result.isTable("allowlist")) {
                globalAllowlists.add(parseAllowlistEntry(result.getTable("allowlist"), "Global Allowlist"));
            } else if (result.isArray("allowlist")) {
                TomlArray allowArray = result.getArray("allowlist");
                for (int i = 0; i < allowArray.size(); i++) {
                    globalAllowlists.add(parseAllowlistEntry(allowArray.getTable(i), "Global Allowlist #" + (i + 1)));
                }
            }
        }

        if (result.contains("allowlists") && result.isArray("allowlists")) {
            TomlArray allowArray = result.getArray("allowlists");
            for (int i = 0; i < allowArray.size(); i++) {
                globalAllowlists.add(parseAllowlistEntry(allowArray.getTable(i), "Global Allowlist #" + (i + 1)));
            }
        }

        TomlArray rulesArray = result.getArray("rules");
        if (rulesArray == null)
            return new GitleaksConfiguration(Collections.emptyList(), globalAllowlists);

        List<GitleaksRule> rules = new ArrayList<>();
        for (int i = 0; i < rulesArray.size(); i++) {
            TomlTable t = rulesArray.getTable(i);
            String id = t.getString("id");
            if (id == null || id.isBlank())
                id = generateId(t);

            try {
                rules.add(parseRule(t, id, sourceName));
            } catch (Exception e) {
                logging.logToError("Skipping invalid rule " + id + ": " + e.getMessage());
            }
        }
        return new GitleaksConfiguration(rules, globalAllowlists);
    }

    private static GitleaksRule parseRule(TomlTable t, String id, String sourceName) {
        String description = t.getString("description");
        double entropy = getDouble(t, "entropy");
        int secretGroup = getInt(t, "secretGroup");
        String regex = t.getString("regex");
        String path = t.getString("path");

        List<String> keywords = toList(t.getArray("keywords"));

        List<GitleaksAllowlist> localAllowlists = extractAllowlists(t, "Rule Allowlist (" + id + ")");

        return new GitleaksRule(id, description, sourceName, entropy, secretGroup, regex, path, keywords,
                localAllowlists);
    }

    private static List<GitleaksAllowlist> extractAllowlists(TomlTable t, String descPrefix) {
        List<GitleaksAllowlist> lists = new ArrayList<>();

        if (t.contains("allowlist")) {
            if (t.isTable("allowlist")) {
                lists.add(parseAllowlistEntry(t.getTable("allowlist"), descPrefix));
            } else if (t.isArray("allowlist")) {
                parseAllowlistArray(t.getArray("allowlist"), lists, descPrefix);
            }
        }

        if (t.contains("allowlists") && t.isArray("allowlists")) {
            parseAllowlistArray(t.getArray("allowlists"), lists, descPrefix);
        }

        return lists;
    }

    private static void parseAllowlistArray(TomlArray arr, List<GitleaksAllowlist> targetList, String descPrefix) {
        for (int i = 0; i < arr.size(); i++) {
            targetList.add(parseAllowlistEntry(arr.getTable(i), descPrefix + " #" + (i + 1)));
        }
    }

    private static GitleaksAllowlist parseAllowlistEntry(TomlTable t, String defaultDescription) {
        String description = t.getString("description");
        if (description == null || description.isBlank()) {
            description = defaultDescription;
        }
        boolean matchAll = "AND".equalsIgnoreCase(t.getString("condition"));
        String regexTarget = t.getString("regexTarget");

        List<Pattern> regexes = parsePatterns(t.getArray("regexes"));
        List<Pattern> paths = parsePatterns(t.getArray("paths"));
        List<String> stopWords = toList(t.getArray("stopwords"));

        return new GitleaksAllowlist(description, regexes, paths, stopWords, matchAll, regexTarget);
    }

    private static GitleaksConfiguration mergeConfigurations(GitleaksConfiguration base,
            GitleaksConfiguration overrides, Logging logging, boolean isDebugEnabled) {
        Map<String, GitleaksRule> ruleMap = new LinkedHashMap<>();

        base.rules().forEach(r -> ruleMap.put(r.getId(), r));

        for (GitleaksRule r : overrides.rules()) {
            if (ruleMap.containsKey(r.getId()) && isDebugEnabled) {
                logging.logToOutput("Overwriting rule: " + r.getId());
            }
            ruleMap.put(r.getId(), r);
        }

        List<GitleaksAllowlist> mergedAllowlists = new ArrayList<>(base.globalAllowlists());
        mergedAllowlists.addAll(overrides.globalAllowlists());

        return new GitleaksConfiguration(new ArrayList<>(ruleMap.values()), mergedAllowlists);
    }

    private static String generateId(TomlTable t) {
        String desc = t.getString("description");
        if (desc != null && !desc.isBlank()) {
            String slug = desc.trim().toLowerCase()
                    .replaceAll("[^a-z0-9]+", "-")
                    .replaceAll("^-|-$", "");

            if (slug.length() > 50) {
                slug = slug.substring(0, 50);

                if (slug.endsWith("-")) {
                    slug = slug.substring(0, slug.length() - 1);
                }
            }
            return slug;
        }

        String regex = t.getString("regex");
        if (regex != null) {
            return "gen-" + Integer.toHexString(regex.hashCode());
        }

        return null;
    }

    private static List<Pattern> parsePatterns(TomlArray arr) {
        if (arr == null)
            return Collections.emptyList();
        List<Pattern> patterns = new ArrayList<>();
        for (int i = 0; i < arr.size(); i++) {
            try {
                patterns.add(Pattern.compile(arr.getString(i), Pattern.CASE_INSENSITIVE));
            } catch (PatternSyntaxException ignored) {
            }
        }
        return patterns;
    }

    private static List<String> toList(TomlArray arr) {
        if (arr == null)
            return Collections.emptyList();
        List<String> list = new ArrayList<>();
        for (int i = 0; i < arr.size(); i++)
            list.add(arr.getString(i));
        return list;
    }

    private static double getDouble(TomlTable t, String key) {
        Object obj = t.get(key);
        if (obj instanceof Number n)
            return n.doubleValue();
        return 0.0;
    }

    private static int getInt(TomlTable t, String key) {
        Object obj = t.get(key);
        if (obj instanceof Number n)
            return n.intValue();
        return 0;
    }
}