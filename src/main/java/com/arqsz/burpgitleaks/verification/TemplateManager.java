package com.arqsz.burpgitleaks.verification;

import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.tomlj.Toml;
import org.tomlj.TomlParseResult;
import org.tomlj.TomlTable;

import burp.api.montoya.logging.Logging;

public class TemplateManager {

    private final Map<String, VerificationTemplate> templates = new HashMap<>();

    private final String TEMPLATE_DIR = "verification";

    private Logging logging;

    public TemplateManager(Logging logging) {
        this.logging = logging;
        discoverAndLoadTemplates();
    }

    private void discoverAndLoadTemplates() {
        try {
            URL dirUrl = getClass().getClassLoader().getResource(TEMPLATE_DIR);

            if (dirUrl == null) {
                logging.logToError("Could not find verification directory in classpath.");
                return;
            }

            if (dirUrl.getProtocol().equals("file")) {
                loadFromDirectory(Paths.get(dirUrl.toURI()));
            } else if (dirUrl.getProtocol().equals("jar")) {
                loadFromJar(dirUrl);
            }

        } catch (Exception e) {
            logging.logToError("Failed to load verification templates: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void loadFromDirectory(Path dirPath) throws IOException {
        try (var stream = Files.walk(dirPath, 1)) {
            stream.filter(p -> p.toString().endsWith(".toml"))
                    .forEach(p -> loadProvider("/" + TEMPLATE_DIR + "/" + p.getFileName().toString()));
        }
    }

    private void loadFromJar(URL url) throws IOException {
        JarURLConnection connection = (JarURLConnection) url.openConnection();
        try (JarFile jarFile = connection.getJarFile()) {
            Enumeration<JarEntry> entries = jarFile.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();

                if (name.startsWith(TEMPLATE_DIR + "/") && name.endsWith(".toml")) {
                    if (!entry.isDirectory()) {
                        loadProvider("/" + name);
                    }
                }
            }
        }
    }

    private void loadProvider(String resourcePath) {
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is == null)
                return;

            TomlParseResult result = Toml.parse(is);
            if (result.hasErrors()) {
                logging.logToError("TOML Syntax error in " + resourcePath + ": " + result.errors());
                return;
            }

            for (String ruleId : result.keySet()) {
                if (!result.isTable(ruleId))
                    continue;

                TomlTable t = result.getTable(ruleId);

                Map<String, String> headers = new HashMap<>();
                if (t.isTable("headers")) {
                    TomlTable headerTable = t.getTable("headers");
                    for (String h : headerTable.keySet()) {
                        headers.put(h, headerTable.getString(h));
                    }
                }

                VerificationTemplate tmpl = new VerificationTemplate(
                        t.getString("name"),
                        t.getString("type") != null ? t.getString("type") : "http",
                        t.getString("method"),
                        t.getString("url"),
                        t.getString("body"),
                        t.getString("username"),
                        t.getString("password"),
                        t.getString("command"),
                        headers);

                templates.put(ruleId, tmpl);
            }
        } catch (IOException e) {
            logging.logToError("Failed to load verification template: " + resourcePath);
        }
    }

    public VerificationTemplate getTemplate(String ruleId) {
        return templates.get(ruleId);
    }

    public boolean hasTemplate(String ruleId) {
        return templates.containsKey(ruleId);
    }
}