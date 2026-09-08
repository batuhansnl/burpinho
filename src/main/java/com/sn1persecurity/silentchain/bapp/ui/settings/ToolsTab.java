package com.sn1persecurity.silentchain.bapp.ui.settings;

import com.sn1persecurity.silentchain.bapp.tools.ToolInfo;
import com.sn1persecurity.silentchain.bapp.tools.ToolRegistry;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;

/**
 * Settings tab that shows the status of all external security tools.
 * Shows which tools are installed, their paths, and install commands for missing ones.
 */
public class ToolsTab extends JPanel {

    private final ToolRegistry registry;
    private final DefaultTableModel tableModel;
    private final JLabel summaryLabel;

    public ToolsTab(ToolRegistry registry) {
        this.registry = registry;
        setLayout(new BorderLayout(0, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top: Summary + Refresh ----
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        summaryLabel = new JLabel(registry.statusSummary());
        summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.BOLD));
        topPanel.add(summaryLabel);

        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> onRefresh());
        topPanel.add(refreshBtn);

        add(topPanel, BorderLayout.NORTH);

        // ---- Center: Tools table ----
        tableModel = new DefaultTableModel(
                new String[]{"Tool", "Category", "Status", "Description", "Install Command"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(tableModel);
        table.getColumnModel().getColumn(0).setPreferredWidth(100);
        table.getColumnModel().getColumn(1).setPreferredWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(80);
        table.getColumnModel().getColumn(3).setPreferredWidth(200);
        table.getColumnModel().getColumn(4).setPreferredWidth(300);

        // Color the status column
        table.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, column);
                if ("INSTALLED".equals(value)) {
                    c.setForeground(new Color(63, 185, 80));
                } else {
                    c.setForeground(new Color(248, 81, 73));
                }
                return c;
            }
        });

        add(new JScrollPane(table), BorderLayout.CENTER);

        // ---- Bottom: Help text ----
        JTextArea help = new JTextArea(
                "These tools must be installed on your system to use Recon and Scanner modules.\n" +
                "Tools that are not installed will be silently skipped during scans.\n" +
                "Most tools can be installed via 'go install' or your package manager.\n\n" +
                "Required tools (marked with *) are needed for the module to be useful.\n" +
                "Optional tools provide additional capabilities when available.");
        help.setEditable(false);
        help.setOpaque(false);
        help.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        help.setFont(help.getFont().deriveFont(Font.PLAIN, 11));
        add(help, BorderLayout.SOUTH);

        // Load initial data
        load();
    }

    public void load() {
        tableModel.setRowCount(0);
        List<ToolInfo> allTools = registry.getAllTools();

        for (ToolInfo info : allTools) {
            boolean installed = registry.isInstalled(info.name());
            String status = installed ? "INSTALLED" : "MISSING";
            String name = info.name() + (info.required() ? " *" : "");

            tableModel.addRow(new Object[]{
                    name,
                    info.category().name(),
                    status,
                    info.description(),
                    installed ? "—" : info.installCmd()
            });
        }

        summaryLabel.setText(registry.statusSummary());
    }

    private void onRefresh() {
        registry.refresh();
        registry.scanAll();
        load();
    }
}
