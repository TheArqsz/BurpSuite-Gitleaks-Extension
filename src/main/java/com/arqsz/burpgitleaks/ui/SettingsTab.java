package com.arqsz.burpgitleaks.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;

import com.arqsz.burpgitleaks.config.GitleaksRule;
import com.arqsz.burpgitleaks.config.PluginSettings;
import com.arqsz.burpgitleaks.config.RuleLoader;
import com.arqsz.burpgitleaks.config.RuleLoader.GitleaksConfiguration;
import com.arqsz.burpgitleaks.scan.GitleaksScanCheck;

import burp.api.montoya.MontoyaApi;

public class SettingsTab extends JPanel {

    private final MontoyaApi api;
    private final GitleaksScanCheck scanCheck;
    private final PluginSettings settings;
    private final ExecutorService executor;
    private final RulesTableModel rulesModel;
    private List<GitleaksRule> currentRules;

    private final JLabel statusLabel = new JLabel("Ready");
    private final JLabel configSourceBadge = new JLabel("") {
        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(getBackground());
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
            super.paintComponent(g2);
            g2.dispose();
        }
    };
    private final Consumer<Boolean> onIssuesTabVisibilityChange;

    public SettingsTab(MontoyaApi api, GitleaksScanCheck scanCheck, PluginSettings settings,
            List<GitleaksRule> initialRules, Consumer<Boolean> onIssuesTabVisibilityChange) {
        this.api = api;
        this.scanCheck = scanCheck;
        this.settings = settings;
        this.currentRules = initialRules;
        this.onIssuesTabVisibilityChange = onIssuesTabVisibilityChange;
        this.rulesModel = new RulesTableModel(initialRules, settings.getDisabledRules());
        this.executor = Executors.newSingleThreadExecutor();

        setLayout(new BorderLayout());

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Configuration", createConfigPanel());
        tabs.addTab("Rules Manager", createRulesPanel());
        tabs.addTab("Scanning Options", createOptionsPanel());

        tabs.addChangeListener(e -> {
            if (tabs.getSelectedIndex() == 0) {
                updateStatusLabel();
            }
        });

        add(tabs, BorderLayout.CENTER);

        SwingUtilities.invokeLater(() -> {
            updateStatusLabel();
            updateConfigSourceDisplay(settings.getCustomPath());
        });
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    private JPanel createConfigPanel() {
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.NORTHWEST;

        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 3;
        form.add(createHeader("Base Configuration"), c);

        c.gridy++;
        c.gridwidth = 1;
        c.weightx = 0;
        form.add(new JLabel("Rule Source URL:"), c);

        c.gridx = 1;
        c.weightx = 1.0;
        JTextField urlField = new JTextField(settings.getUrl());
        form.add(urlField, c);

        c.gridx = 2;
        c.weightx = 0;
        JPanel urlBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));

        JButton saveUrlBtn = new JButton("Save");
        saveUrlBtn.setToolTipText("Save the current URL as the update source.");
        saveUrlBtn.addActionListener(e -> {
            settings.setUrl(urlField.getText().trim());
            Toast.success(this, "Configuration URL saved!");
        });

        JButton resetUrlBtn = new JButton("Reset URL to default");
        resetUrlBtn.setToolTipText("Restore the official Gitleaks repository URL.");
        resetUrlBtn.addActionListener(e -> {
            urlField.setText(RuleLoader.OFFICIAL_URL);
            settings.setUrl(RuleLoader.OFFICIAL_URL);
            Toast.info(this, "Restored official Gitleaks URL.");
        });

        urlBtnPanel.add(saveUrlBtn);
        urlBtnPanel.add(Box.createHorizontalStrut(5));
        urlBtnPanel.add(resetUrlBtn);
        form.add(urlBtnPanel, c);

        c.gridx = 1;
        c.gridy++;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;

        JButton updateBtn = new JButton("Download the latest config & Update rules");
        updateBtn.setFont(updateBtn.getFont().deriveFont(Font.BOLD, 12f));
        updateBtn.addActionListener(e -> performUpdate());
        form.add(updateBtn, c);

        c.gridx = 0;
        c.gridy++;
        c.gridwidth = 3;
        c.fill = GridBagConstraints.HORIZONTAL;
        form.add(Box.createVerticalStrut(20), c);

        c.gridy++;
        form.add(createHeader("Extensions & Overrides"), c);

        c.gridy++;
        c.gridwidth = 1;
        c.weightx = 0;
        form.add(new JLabel("Custom Config File:"), c);

        c.gridx = 1;
        c.weightx = 1.0;
        JTextField pathField = new JTextField(settings.getCustomPath());
        pathField.addActionListener(e -> {
            String cleanPath = pathField.getText().trim();
            settings.setCustomPath(cleanPath);
            reloadEngine();
        });
        form.add(pathField, c);

        c.gridx = 2;
        c.weightx = 0;
        JPanel fileBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));

        JButton browseBtn = new JButton("Browse...");
        browseBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                pathField.setText(fc.getSelectedFile().getAbsolutePath());
                settings.setCustomPath(pathField.getText().trim());
                reloadEngine();
            }
        });

        JButton clearBtn = new JButton("Clear & Reset rules");
        clearBtn.setPreferredSize(resetUrlBtn.getPreferredSize());
        clearBtn.setToolTipText("Remove custom configuration and revert to default rules.");
        clearBtn.addActionListener(e -> {
            pathField.setText("");
            settings.setCustomPath("");

            reloadEngine();
        });

        fileBtnPanel.add(browseBtn);
        fileBtnPanel.add(Box.createHorizontalStrut(5));
        fileBtnPanel.add(clearBtn);
        form.add(fileBtnPanel, c);

        c.gridx = 0;
        c.gridy++;
        c.gridwidth = 3;
        c.weightx = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        form.add(Box.createVerticalStrut(20), c);

        c.gridy++;
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 0));
        statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 14f));

        configSourceBadge.setOpaque(false);
        configSourceBadge.setForeground(Color.WHITE);
        configSourceBadge.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
        configSourceBadge.setFont(configSourceBadge.getFont().deriveFont(Font.BOLD, 11f));

        statusPanel.add(statusLabel);
        statusPanel.add(configSourceBadge);

        form.add(statusPanel, c);

        c.gridy++;
        c.weighty = 1.0;
        c.fill = GridBagConstraints.BOTH;
        form.add(new JPanel(), c);

        return form;
    }

    private JPanel createRulesPanel() {
        JPanel p = new JPanel(new BorderLayout(5, 10));
        p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel searchPanel = new JPanel(new BorderLayout(5, 0));
        searchPanel.add(new JLabel("Filter Rules: "), BorderLayout.WEST);
        JTextField searchField = new JTextField();
        searchPanel.add(searchField, BorderLayout.CENTER);
        p.add(searchPanel, BorderLayout.NORTH);

        JTable table = new JTable(rulesModel);
        table.setFillsViewportHeight(true);
        table.setRowHeight(24);

        TableRowSorter<RulesTableModel> sorter = new TableRowSorter<>(rulesModel);
        table.setRowSorter(sorter);

        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                filter();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                filter();
            }

            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                filter();
            }

            private void filter() {
                String text = searchField.getText();
                if (text.trim().length() == 0)
                    sorter.setRowFilter(null);
                else
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
            }
        });

        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);
        table.getColumnModel().getColumn(1).setMaxWidth(150);
        table.getColumnModel().getColumn(2).setPreferredWidth(200);
        table.getColumnModel().getColumn(3).setPreferredWidth(400);

        p.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton applyBtn = new JButton("Apply Changes");
        applyBtn.setFont(applyBtn.getFont().deriveFont(Font.BOLD, 12f));
        applyBtn.addActionListener(e -> {
            settings.setDisabledRules(rulesModel.getDisabledIds());
            updateStatusLabel();
            Toast.success(this, "Rules updated. Engine reloaded.");
        });
        bottomPanel.add(applyBtn);
        p.add(bottomPanel, BorderLayout.SOUTH);

        return p;
    }

    private JPanel createOptionsPanel() {
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(10, 10, 10, 10);
        c.anchor = GridBagConstraints.NORTHWEST;

        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 2;
        form.add(createHeader("Detection Logic"), c);

        c.gridy++;
        c.gridwidth = 2;
        JCheckBox scopeCb = new JCheckBox("Scan only in-scope items");
        scopeCb.setToolTipText(
                "If checked, the extension will ignore traffic that is not in the Burp Suite Target Scope.");
        scopeCb.setSelected(settings.isScanInScopeOnly());
        scopeCb.addActionListener(e -> settings.setScanInScopeOnly(scopeCb.isSelected()));
        form.add(scopeCb, c);

        c.gridy++;
        c.gridwidth = 2;
        JCheckBox allowCb = new JCheckBox("Ignore 'gitleaks:allow' comments");
        allowCb.setToolTipText(
                "If checked, secrets will be reported even if they are marked as allowed in the source code.");
        allowCb.setSelected(settings.getIgnoreGitleaksAllow());
        allowCb.addActionListener(e -> settings.setIgnoreGitleaksAllow(allowCb.isSelected()));
        form.add(allowCb, c);

        c.gridy++;
        JCheckBox debugCb = new JCheckBox("Enable debug logging");
        debugCb.setToolTipText("Log verbose details about allowed/ignored secrets to the Burp extension output.");
        debugCb.setSelected(settings.isDebugEnabled());
        debugCb.addActionListener(e -> settings.setDebugEnabled(debugCb.isSelected()));
        form.add(debugCb, c);

        c.gridy++;
        form.add(Box.createVerticalStrut(10), c);
        c.gridy++;
        form.add(createHeader("Reporting & Display"), c);

        c.gridy++;
        c.gridwidth = 2;
        JCheckBox issuesTabCb = new JCheckBox(
                "[Experimental] Enable 'Gitleaks Issues' tab (Community Edition workaround)");
        issuesTabCb.setToolTipText("Displays a custom table of findings as a separate top-level tab.");
        issuesTabCb.setSelected(settings.isShowIssuesTab());
        issuesTabCb.addActionListener(e -> {
            boolean enabled = issuesTabCb.isSelected();
            settings.setShowIssuesTab(enabled);

            onIssuesTabVisibilityChange.accept(enabled);
        });
        form.add(issuesTabCb, c);

        c.gridy++;
        c.gridwidth = 1;
        c.weightx = 0;
        form.add(new JLabel("Redaction Level:"), c);

        c.gridx = 1;
        c.weightx = 1.0;
        JSpinner redactSpinner = new JSpinner(new SpinnerNumberModel(settings.getRedactionLevel(), 0, 100, 10));
        redactSpinner.addChangeListener(e -> settings.setRedactionLevel((Integer) redactSpinner.getValue()));

        JPanel spinnerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        spinnerPanel.add(redactSpinner);
        spinnerPanel.add(Box.createHorizontalStrut(10));
        spinnerPanel.add(new JLabel("% (0 = Reveal All, 100 = Hide All)"));
        form.add(spinnerPanel, c);

        c.gridx = 0;
        c.gridy++;
        c.weighty = 1.0;
        c.gridwidth = 2;
        c.fill = GridBagConstraints.BOTH;
        form.add(new JPanel(), c);

        return form;
    }

    private JLabel createHeader(String text) {
        JLabel l = new JLabel(text);
        l.putClientProperty("FlatLaf.styleClass", "h3");
        l.setFont(l.getFont().deriveFont(Font.BOLD, 16f));
        l.setForeground(UIManager.getColor("Label.disabledForeground"));
        return l;
    }

    private void performUpdate() {
        statusLabel.setText("Updating...");
        statusLabel.setForeground(Color.BLUE);

        executor.submit(() -> {
            try {
                String msg = RuleLoader.updateRules(api, settings.getUrl());
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText(msg);
                    statusLabel.setForeground(new Color(0, 150, 0));
                    reloadEngine();
                    Toast.success(this, "Update Successful!");
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Error: " + e.getMessage());
                    statusLabel.setForeground(Color.RED);
                    Toast.error(this, "Update Failed: " + e.getMessage());
                });
            }
        });
    }

    private void reloadEngine() {
        statusLabel.setText("Reloading...");
        statusLabel.setForeground(Color.BLUE);

        String customPath = settings.getCustomPath();

        executor.submit(() -> {
            try {
                GitleaksConfiguration newConfig = RuleLoader.loadConfiguration(customPath, api.logging(),
                        settings.isDebugEnabled());

                SwingUtilities.invokeLater(() -> {
                    applyRules(newConfig);
                    updateStatusLabel();
                    updateConfigSourceDisplay(customPath);

                    if (customPath != null && !customPath.trim().isBlank()) {
                        Toast.info(this, "Custom config loaded from: " + customPath);
                        Toast.success(this, "Configuration loaded (with overrides)!");
                    } else {
                        Toast.success(this, "Base configuration loaded.");
                    }
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    api.logging().logToError("Config load error: " + e.getMessage());
                    statusLabel.setText("Error loading config");
                    statusLabel.setForeground(Color.RED);
                    Toast.error(this, "Config load error: " + e.getMessage());

                    try {
                        GitleaksConfiguration fallbackConfig = RuleLoader.loadConfiguration(null, api.logging(),
                                settings.isDebugEnabled());
                        applyRules(fallbackConfig);
                        updateStatusLabel();

                        Toast.info(this, "Reverted to default rules due to configuration error.");
                    } catch (Exception fatal) {
                        statusLabel.setText("Critical Error: " + fatal.getMessage());
                        statusLabel.setForeground(Color.RED);
                    }
                });
            }
        });
    }

    private void applyRules(GitleaksConfiguration config) {
        this.currentRules = config.rules();
        scanCheck.updateConfig(config);
        rulesModel.setRules(config.rules(), settings.getDisabledRules());
    }

    private void updateStatusLabel() {
        if (currentRules == null)
            return;

        List<String> disabledIds = settings.getDisabledRules();
        int total = currentRules.size();
        long enabledCount = currentRules.stream()
                .filter(r -> !disabledIds.contains(r.getId()))
                .count();

        statusLabel.setText("Active Rules: " + enabledCount + " / " + total);

        if (enabledCount == 0 && total > 0) {
            statusLabel.setForeground(Color.RED);
        } else if (enabledCount < total) {
            statusLabel.setForeground(new Color(204, 102, 0));
        } else {
            statusLabel.setForeground(new Color(0, 150, 0));
        }
    }

    private void updateConfigSourceDisplay(String customPath) {
        if (customPath != null && !customPath.isBlank()) {
            setConfigBadge("Custom File", new Color(0, 102, 204));
        } else if (Files.exists(RuleLoader.LOCAL_CONFIG_PATH)) {
            setConfigBadge("Local Config", new Color(255, 140, 0));
        } else {
            setConfigBadge("Bundled Config", new Color(100, 100, 100));
        }

        if (configSourceBadge.getParent() != null) {
            configSourceBadge.getParent().revalidate();
            configSourceBadge.getParent().repaint();
        }
    }

    private void setConfigBadge(String text, Color bg) {
        configSourceBadge.setText(text);
        configSourceBadge.setBackground(bg);
        configSourceBadge.repaint();
    }

    private static class RulesTableModel extends AbstractTableModel {
        private final String[] cols = { "Enabled", "Source", "Rule ID", "Description" };
        private List<GitleaksRule> rules;
        private List<Boolean> enabledState;

        public RulesTableModel(List<GitleaksRule> rules, List<String> disabledIds) {
            setRules(rules, disabledIds);
        }

        public void setRules(List<GitleaksRule> rules, List<String> disabledIds) {
            this.rules = rules;
            this.enabledState = new ArrayList<>();
            for (GitleaksRule r : rules) {
                this.enabledState.add(!disabledIds.contains(r.getId()));
            }
            fireTableDataChanged();
        }

        public List<String> getDisabledIds() {
            List<String> disabled = new ArrayList<>();
            for (int i = 0; i < rules.size(); i++) {
                if (!enabledState.get(i))
                    disabled.add(rules.get(i).getId());
            }
            return disabled;
        }

        @Override
        public int getRowCount() {
            return rules.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int col) {
            return cols[col];
        }

        @Override
        public Class<?> getColumnClass(int col) {
            return col == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return col == 0;
        }

        @Override
        public Object getValueAt(int row, int col) {
            GitleaksRule rule = rules.get(row);
            switch (col) {
                case 0:
                    return enabledState.get(row);
                case 1:
                    return rule.getSource();
                case 2:
                    return rule.getId();
                case 3:
                    return rule.getDescription();
                default:
                    return null;
            }
        }

        @Override
        public void setValueAt(Object val, int row, int col) {
            if (col == 0)
                enabledState.set(row, Boolean.TRUE.equals(val));
            fireTableCellUpdated(row, col);
        }
    }
}