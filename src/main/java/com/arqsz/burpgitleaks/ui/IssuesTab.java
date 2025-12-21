package com.arqsz.burpgitleaks.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;

import com.arqsz.burpgitleaks.utils.IssueUtils;
import com.arqsz.burpgitleaks.verification.TemplateManager;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

public class IssuesTab extends JPanel {

    private final MontoyaApi api;
    private final IssuesTableModel model;
    private final JTable table;
    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;
    private final JEditorPane advisoryPane;

    private final VerificationMenuFactory menuFactory;

    private String tabTitle;
    private static final String DEFAULT_TAB_TITLE = "Gitleaks Issues";

    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss dd MMM yyyy");

    public IssuesTab(MontoyaApi api, String tabTitle, TemplateManager templateManager) {
        this.api = api;
        if (tabTitle == null || tabTitle.isBlank()) {
            this.tabTitle = DEFAULT_TAB_TITLE;
        } else {
            this.tabTitle = tabTitle;
        }

        this.menuFactory = new VerificationMenuFactory(api, templateManager);

        this.model = new IssuesTableModel();

        setLayout(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(new JLabel("Filter:"));
        JTextField filterField = new JTextField(20);

        JButton clearBtn = new JButton("Clear Issues");
        clearBtn.addActionListener(e -> {
            model.clear();
            resetViewers();
            updateTabTitle(0);
        });
        topPanel.add(filterField);
        topPanel.add(clearBtn);

        add(topPanel, BorderLayout.NORTH);

        table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setRowHeight(22);

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        table.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.getColumnModel().getColumn(0).setPreferredWidth(40);

        table.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(1).setMaxWidth(150);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);

        table.getColumnModel().getColumn(2).setMaxWidth(500);
        table.getColumnModel().getColumn(2).setPreferredWidth(200);

        table.getColumnModel().getColumn(3).setMaxWidth(500);
        table.getColumnModel().getColumn(3).setPreferredWidth(300);

        table.getColumnModel().getColumn(4).setCellRenderer(new SeverityRenderer());
        table.getColumnModel().getColumn(4).setMinWidth(80);
        table.getColumnModel().getColumn(4).setMaxWidth(100);
        table.getColumnModel().getColumn(4).setPreferredWidth(90);

        table.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(5).setMinWidth(80);
        table.getColumnModel().getColumn(5).setMaxWidth(100);
        table.getColumnModel().getColumn(5).setPreferredWidth(90);

        TableRowSorter<IssuesTableModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        filterField.addActionListener(e -> {
            String text = filterField.getText();
            if (text.trim().length() == 0)
                sorter.setRowFilter(null);
            else
                sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
        });

        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> sendSelectedToRepeater());

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copySelectedUrls());

        JMenuItem deleteItem = new JMenuItem("Delete Selected Issue(s)");
        deleteItem.addActionListener(e -> deleteSelectedIssues());

        popupMenu.add(sendToRepeater);
        popupMenu.add(copyUrl);
        popupMenu.addSeparator();
        popupMenu.add(deleteItem);

        final int staticItemCount = popupMenu.getComponentCount();

        popupMenu.addSeparator();

        popupMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                while (popupMenu.getComponentCount() > staticItemCount) {
                    popupMenu.remove(popupMenu.getComponentCount() - 1);
                }

                int[] rows = table.getSelectedRows();
                if (rows.length == 1) {
                    int modelRow = table.convertRowIndexToModel(rows[0]);
                    AuditIssue issue = model.getIssue(modelRow);

                    String ruleId = IssueUtils.extractRuleId(issue);
                    String secret = IssueUtils.extractSecret(issue);

                    List<JMenuItem> verifyItems = menuFactory.createMenuItems(ruleId, secret);

                    if (!verifyItems.isEmpty()) {
                        popupMenu.addSeparator();
                        for (JMenuItem item : verifyItems) {
                            popupMenu.add(item);
                        }
                    }
                }
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
            }
        });

        table.setComponentPopupMenu(popupMenu);

        JScrollPane tableScroll = new JScrollPane(table);

        JTabbedPane detailTabs = new JTabbedPane();

        advisoryPane = new JEditorPane();
        advisoryPane.setContentType("text/html");
        advisoryPane.setEditable(false);
        advisoryPane.setBorder(new EmptyBorder(10, 10, 10, 10));
        detailTabs.addTab("Advisory", new JScrollPane(advisoryPane));

        requestViewer = api.userInterface().createHttpRequestEditor();
        detailTabs.addTab("Request", requestViewer.uiComponent());

        responseViewer = api.userInterface().createHttpResponseEditor();
        detailTabs.addTab("Response", responseViewer.uiComponent());

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(300);

        add(splitPane, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    AuditIssue issue = model.getIssue(modelRow);
                    displayIssue(issue);
                }
            }
        });
    }

    public boolean addIssue(AuditIssue issue) {
        if (SwingUtilities.isEventDispatchThread()) {
            boolean added = model.add(issue);
            if (added) {
                updateTabTitle(model.getRowCount());
            }
            return added;
        }

        final boolean[] result = new boolean[1];

        try {
            SwingUtilities.invokeAndWait(() -> {
                result[0] = model.add(issue);
                if (result[0]) {
                    updateTabTitle(model.getRowCount());
                }
            });
        } catch (Exception e) {
            api.logging().logToError("Error adding issue to tab: " + e.getMessage());
            return false;
        }

        return result[0];
    }

    private void deleteSelectedIssues() {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0)
            return;

        int[] modelRows = Arrays.stream(selectedRows)
                .map(table::convertRowIndexToModel)
                .sorted()
                .toArray();

        for (int i = modelRows.length - 1; i >= 0; i--) {
            model.removeRow(modelRows[i]);
        }

        updateTabTitle(model.getRowCount());

        if (table.getSelectedRow() == -1) {
            resetViewers();
        }
    }

    private void sendSelectedToRepeater() {
        List<AuditIssue> selectedIssues = getSelectedIssues();
        for (AuditIssue issue : selectedIssues) {
            if (!issue.requestResponses().isEmpty()) {
                HttpRequestResponse reqRes = issue.requestResponses().get(0);
                api.repeater().sendToRepeater(reqRes.request(), issue.name());
            }
        }
    }

    private void copySelectedUrls() {
        List<AuditIssue> selectedIssues = getSelectedIssues();
        if (selectedIssues.isEmpty())
            return;

        StringBuilder sb = new StringBuilder();
        for (AuditIssue issue : selectedIssues) {
            sb.append(issue.baseUrl()).append("\n");
        }

        copyToClipboard(sb.toString().trim());
    }

    private List<AuditIssue> getSelectedIssues() {
        int[] selectedRows = table.getSelectedRows();
        List<AuditIssue> list = new ArrayList<>();
        if (selectedRows.length == 0)
            return list;

        for (int viewRow : selectedRows) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            list.add(model.getIssue(modelRow));
        }
        return list;
    }

    private void copyToClipboard(String text) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(new StringSelection(text), null);
    }

    private void updateTabTitle(int count) {
        SwingUtilities.invokeLater(() -> {
            Component currentComponent = this;
            Container parent = currentComponent.getParent();

            while (parent != null) {
                if (parent instanceof JTabbedPane tabbedPane) {
                    int index = tabbedPane.indexOfComponent(currentComponent);

                    if (index != -1) {
                        String newTitle = tabTitle;
                        if (count > 0) {
                            newTitle += " (" + count + ")";
                            tabbedPane.setBackgroundAt(index, new Color(255, 128, 0));
                        } else {
                            tabbedPane.setBackgroundAt(index, null);
                        }
                        if (!newTitle.equals(tabbedPane.getTitleAt(index))) {
                            tabbedPane.setTitleAt(index, newTitle);
                        }
                    }
                    return;
                }
                currentComponent = parent;
                parent = parent.getParent();
            }
        });
    }

    private void displayIssue(AuditIssue issue) {
        advisoryPane.setText(buildAdvisoryHtml(issue));
        advisoryPane.setCaretPosition(0);

        List<HttpRequestResponse> evidence = issue.requestResponses();
        if (!evidence.isEmpty()) {
            HttpRequestResponse reqRes = evidence.get(0);
            requestViewer.setRequest(reqRes.request());
            responseViewer.setResponse(reqRes.response());
        } else {
            resetViewers();
        }
    }

    private void resetViewers() {
        advisoryPane.setText("");
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);
    }

    private String buildAdvisoryHtml(AuditIssue issue) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body style='font-family: sans-serif; padding: 10px;'>");

        sb.append("<h2 style='color: #E05206;'>").append(issue.name()).append("</h2>");

        sb.append("<table style='margin-bottom: 15px; width: 100%; border-collapse: collapse;'>");
        sb.append("<tr><td width='100' style='padding: 3px;'><b>Severity:</b></td><td>")
                .append(colorizeSeverityHtml(issue.severity())).append("</td></tr>");
        sb.append("<tr><td style='padding: 3px;'><b>Confidence:</b></td><td>").append(issue.confidence().name())
                .append("</td></tr>");
        sb.append("<tr><td style='padding: 3px;'><b>Host:</b></td><td>").append(issue.httpService().host())
                .append("</td></tr>");
        sb.append("<tr><td style='padding: 3px;'><b>Path:</b></td><td>").append(issue.baseUrl()).append("</td></tr>");

        sb.append("<tr><td style='padding: 3px;'><b>Location:</b></td><td>").append(calculateLocation(issue))
                .append("</td></tr>");

        sb.append("</table>");

        if (issue.detail() != null && !issue.detail().isBlank()) {
            sb.append("<h3 style='border-bottom: 1px solid #ccc; padding-bottom: 5px;'>Issue Detail</h3>");
            sb.append("<div style='margin-bottom: 15px;'>").append(issue.detail()).append("</div>");
        }

        if (issue.remediation() != null && !issue.remediation().isBlank()) {
            sb.append("<h3 style='border-bottom: 1px solid #ccc; padding-bottom: 5px;'>Remediation</h3>");
            sb.append("<div style='margin-bottom: 15px;'>").append(issue.remediation()).append("</div>");
        }

        sb.append("</body></html>");
        return sb.toString();
    }

    private String calculateLocation(AuditIssue issue) {
        if (issue.requestResponses().isEmpty())
            return "Unknown";

        HttpRequestResponse reqRes = issue.requestResponses().get(0);
        List<Marker> markers = reqRes.responseMarkers();
        String content;
        String prefix = "Response";

        if (markers == null || markers.isEmpty()) {
            markers = reqRes.requestMarkers();
            if (markers == null || markers.isEmpty())
                return "Path / Header Match";
            content = reqRes.request().toString();
            prefix = "Request";
        } else {
            content = reqRes.response().toString();
        }

        if (content == null || content.isEmpty())
            return "Empty content";

        Marker m = markers.get(0);
        int offset = m.range().startIndexInclusive();

        return calculateLineCol(content, offset, prefix);
    }

    private String calculateLineCol(String content, int offset, String prefix) {
        if (offset < 0 || offset > content.length())
            return prefix + " Offset: " + offset;

        int lineNumber = 1;
        int lastNewlineIndex = -1;

        for (int i = 0; i < offset; i++) {
            if (content.charAt(i) == '\n') {
                lineNumber++;
                lastNewlineIndex = i;
            }
        }

        int columnNumber = offset - lastNewlineIndex;

        return String.format("%s Line %d, Column %d (Character Offset %d)", prefix, lineNumber, columnNumber, offset);
    }

    private String colorizeSeverityHtml(AuditIssueSeverity severity) {
        String color = switch (severity) {
            case HIGH -> "#D32F2F";
            case MEDIUM -> "#FB8C00";
            case LOW -> "#1976D2";
            case INFORMATION -> "#757575";
            default -> "#000000";
        };
        return "<span style='color: " + color + "; font-weight: bold;'>" + severity.name() + "</span>";
    }

    private static class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
                int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            String severity = (String) value;
            if (!isSelected) {
                switch (severity) {
                    case "HIGH":
                        c.setBackground(new Color(255, 204, 204));
                        c.setForeground(new Color(153, 0, 0));
                        break;
                    case "MEDIUM":
                        c.setBackground(new Color(255, 229, 204));
                        c.setForeground(new Color(204, 102, 0));
                        break;
                    case "LOW":
                        c.setBackground(new Color(204, 229, 255));
                        c.setForeground(new Color(0, 51, 153));
                        break;
                    case "INFORMATION":
                        c.setBackground(new Color(245, 245, 245));
                        c.setForeground(Color.BLACK);
                        break;
                    default:
                        c.setBackground(Color.WHITE);
                        c.setForeground(Color.BLACK);
                }
            } else {
                c.setFont(c.getFont().deriveFont(Font.BOLD));
            }
            setHorizontalAlignment(JLabel.CENTER);
            return c;
        }
    }

    private record IssueEntry(int id, String timestamp, AuditIssue issue) {
    }

    private static class IssuesTableModel extends AbstractTableModel {
        private final List<IssueEntry> entries = new ArrayList<>();
        private final Set<String> issueSignatures = new HashSet<>();
        private int nextId = 1;
        private final String[] cols = { "#", "Time", "Name", "URL", "Severity", "Confidence" };

        public boolean add(AuditIssue issue) {
            String sig = generateSignature(issue);
            if (!issueSignatures.contains(sig)) {
                issueSignatures.add(sig);
                String now = LocalDateTime.now().format(TIMESTAMP_FORMAT);
                entries.add(new IssueEntry(nextId++, now, issue));
                fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
                return true;
            }
            return false;
        }

        public void removeRow(int row) {
            if (row >= 0 && row < entries.size()) {
                IssueEntry entry = entries.get(row);

                String sig = generateSignature(entry.issue());
                issueSignatures.remove(sig);

                entries.remove(row);
                fireTableRowsDeleted(row, row);
            }
        }

        public void clear() {
            entries.clear();
            issueSignatures.clear();
            nextId = 1;
            fireTableDataChanged();
        }

        private String generateSignature(AuditIssue i) {
            String detailPart = (i.detail() != null) ? String.valueOf(i.detail().hashCode()) : "0";
            return i.name() + "|" + i.baseUrl() + "|" + detailPart;
        }

        public AuditIssue getIssue(int row) {
            return entries.get(row).issue();
        }

        @Override
        public int getRowCount() {
            return entries.size();
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
        public Object getValueAt(int row, int col) {
            IssueEntry e = entries.get(row);
            AuditIssue i = e.issue();
            switch (col) {
                case 0:
                    return e.id();
                case 1:
                    return e.timestamp();
                case 2:
                    return i.name();
                case 3:
                    return i.baseUrl();
                case 4:
                    return i.severity().name();
                case 5:
                    return i.confidence().name();
                default:
                    return "";
            }
        }
    }
}