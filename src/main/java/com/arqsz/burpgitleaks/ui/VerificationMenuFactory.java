package com.arqsz.burpgitleaks.ui;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import com.arqsz.burpgitleaks.verification.CurlGenerator;
import com.arqsz.burpgitleaks.verification.RequestGenerator;
import com.arqsz.burpgitleaks.verification.TemplateManager;
import com.arqsz.burpgitleaks.verification.VerificationTemplate;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

public class VerificationMenuFactory {

    private final MontoyaApi api;
    private final TemplateManager templateManager;

    public VerificationMenuFactory(MontoyaApi api, TemplateManager templateManager) {
        this.api = api;
        this.templateManager = templateManager;
    }

    public List<JMenuItem> createMenuItems(String ruleId, String secret) {
        if (ruleId == null || secret == null || !templateManager.hasTemplate(ruleId)) {
            return Collections.emptyList();
        }

        List<JMenuItem> items = new ArrayList<>();
        VerificationTemplate tmpl = templateManager.getTemplate(ruleId);

        if ("http".equalsIgnoreCase(tmpl.type())) {
            JMenuItem repeaterItem = new JMenuItem("Verification: Send to Repeater");
            repeaterItem.addActionListener(e -> {
                HttpRequest req = RequestGenerator.build(tmpl, secret);
                api.repeater().sendToRepeater(req, "Verification: " + ruleId);
                Toast.success(api.userInterface().swingUtils().suiteFrame(), "Sent to Repeater");
            });
            items.add(repeaterItem);

            JMenuItem curlItem = new JMenuItem("Verification: Copy cURL Command");
            curlItem.addActionListener(e -> {
                String cmd = CurlGenerator.toCurl(tmpl, secret);
                copyToClipboard(cmd);
                Toast.success(api.userInterface().swingUtils().suiteFrame(), "cURL copied");
            });
            items.add(curlItem);
        } else if ("guide".equalsIgnoreCase(tmpl.type())) {
            JMenuItem guideItem = new JMenuItem("Verification: Show Manual Steps");
            guideItem.addActionListener(e -> {
                String text = tmpl.body().replace("{{SECRET}}", secret);
                showInstructionDialog(tmpl.name(), text);
            });
            items.add(guideItem);
        }

        return items;
    }

    private void copyToClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    private void showInstructionDialog(String title, String content) {
        SwingUtilities.invokeLater(() -> {
            JTextArea textArea = new JTextArea(content);
            textArea.setEditable(false);
            textArea.setLineWrap(true);
            textArea.setWrapStyleWord(true);
            JScrollPane scroll = new JScrollPane(textArea);
            scroll.setPreferredSize(new java.awt.Dimension(500, 300));
            JOptionPane.showMessageDialog(null, scroll, "Verification: " + title, JOptionPane.INFORMATION_MESSAGE);
        });
    }
}