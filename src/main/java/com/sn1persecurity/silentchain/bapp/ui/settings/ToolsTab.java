package com.sn1persecurity.silentchain.bapp.ui.settings;

import com.sn1persecurity.silentchain.bapp.tools.ToolInfo;
import com.sn1persecurity.silentchain.bapp.tools.ToolRegistry;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.List;

/**
 * Settings tab that shows the status of all external security tools.
 * Shows which tools are installed, their exact absolute paths, and quick install commands.
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
        summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.BOLD, 13f));
        topPanel.add(summaryLabel);

        JButton refreshBtn = new JButton("Re-scan Tools");
        refreshBtn.addActionListener(e -> onRefresh());
        topPanel.add(refreshBtn);

        JButton copyMacBtn = new JButton("📋 Copy macOS Install (Brew+Go)");
        copyMacBtn.addActionListener(e -> copyToClipboard(
                "brew install nuclei ffuf sqlmap nikto whatweb jq && " +
                "brew install go && " +
                "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest " +
                "github.com/projectdiscovery/httpx/cmd/httpx@latest " +
                "github.com/projectdiscovery/dnsx/cmd/dnsx@latest " +
                "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest " +
                "github.com/projectdiscovery/katana/cmd/katana@latest " +
                "github.com/hahwul/dalfox/v2@latest " +
                "github.com/tomnomnom/assetfinder@latest && " +
                "pip3 install wafw00f"
        ));
        topPanel.add(copyMacBtn);

        JButton copyLinuxBtn = new JButton("📋 Copy Linux Install (Apt+Go)");
        copyLinuxBtn.addActionListener(e -> copyToClipboard(
                "sudo apt update && sudo apt install -y sqlmap nikto whatweb jq golang python3-pip && " +
                "pip3 install wafw00f && " +
                "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest " +
                "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest " +
                "github.com/projectdiscovery/httpx/cmd/httpx@latest " +
                "github.com/projectdiscovery/dnsx/cmd/dnsx@latest " +
                "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest " +
                "github.com/projectdiscovery/katana/cmd/katana@latest " +
                "github.com/hahwul/dalfox/v2@latest " +
                "github.com/ffuf/ffuf/v2@latest " +
                "github.com/tomnomnom/assetfinder@latest"
        ));
        topPanel.add(copyLinuxBtn);

        add(topPanel, BorderLayout.NORTH);

        // ---- Center: Tools table ----
        tableModel = new DefaultTableModel(
                new String[]{"Tool", "Category", "Status", "Detected Path / Install Command", "Description"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(tableModel);
        table.getColumnModel().getColumn(0).setPreferredWidth(110);
        table.getColumnModel().getColumn(1).setPreferredWidth(90);
        table.getColumnModel().getColumn(2).setPreferredWidth(90);
        table.getColumnModel().getColumn(3).setPreferredWidth(320);
        table.getColumnModel().getColumn(4).setPreferredWidth(240);

        // Color the status column
        table.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, column);
                if ("INSTALLED".equals(value)) {
                    c.setForeground(new Color(63, 185, 80));
                    setFont(getFont().deriveFont(Font.BOLD));
                } else {
                    c.setForeground(new Color(248, 81, 73));
                    setFont(getFont().deriveFont(Font.PLAIN));
                }
                return c;
            }
        });

        add(new JScrollPane(table), BorderLayout.CENTER);

        // ---- Bottom: Help text ----
        JTextArea help = new JTextArea(
                "⚡ Dual-Engine Architecture:\n" +
                "  • When CLI tools are installed, burpinho executes them at maximum performance.\n" +
                "  • When CLI tools are missing, burpinho automatically uses built-in pure Java engines\n" +
                "    (Certificate Transparency, multithreaded DNS & HTTP probing, top-ports scanner, WAF header analysis).\n" +
                "  • To install missing tools on your machine, click the copy buttons above and paste into Terminal.");
        help.setEditable(false);
        help.setOpaque(false);
        help.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        help.setFont(help.getFont().deriveFont(Font.PLAIN, 11f));
        add(help, BorderLayout.SOUTH);

        // Load initial data
        load();
    }

    public void load() {
        tableModel.setRowCount(0);
        List<ToolInfo> allTools = registry.getAllTools();

        for (ToolInfo info : allTools) {
            String path = registry.getPath(info.name());
            boolean installed = path != null && !path.isEmpty();
            String status = installed ? "INSTALLED" : "MISSING";
            String name = info.name() + (info.required() ? " *" : "");

            tableModel.addRow(new Object[]{
                    name,
                    info.category().name(),
                    status,
                    installed ? path : info.installCmd(),
                    info.description()
            });
        }

        summaryLabel.setText(registry.statusSummary());
    }

    private void onRefresh() {
        registry.refresh();
        registry.scanAll();
        load();
    }

    private void copyToClipboard(String text) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
            JOptionPane.showMessageDialog(this,
                    "Installation command copied to clipboard!\nOpen Terminal and paste to install tools.",
                    "Command Copied", JOptionPane.INFORMATION_MESSAGE);
        } catch (Throwable ignored) {}
    }
}
