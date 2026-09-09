package com.sn1persecurity.silentchain.bapp.modules.ipscan;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Aggregated result of an IP / CIDR / Network scan run.
 */
public class IpScanResult {

    private final String targetInput;
    private final Map<String, IpHostEntry> hostsMap = new ConcurrentHashMap<>();
    private final List<String> auditLogs = new ArrayList<>();
    private long totalDurationMs = 0;

    public IpScanResult(String targetInput) {
        this.targetInput = targetInput;
    }

    public synchronized IpHostEntry getOrCreateHost(String ip) {
        return hostsMap.computeIfAbsent(ip.trim(), IpHostEntry::new);
    }

    public List<IpHostEntry> getHosts() {
        return new ArrayList<>(hostsMap.values());
    }

    public List<IpHostEntry> getAliveHosts() {
        List<IpHostEntry> list = new ArrayList<>();
        for (IpHostEntry h : hostsMap.values()) {
            if (h.isAlive()) list.add(h);
        }
        return list;
    }

    public synchronized void addAuditLog(String log) {
        auditLogs.add(log);
    }

    public synchronized List<String> getAuditLogs() {
        return new ArrayList<>(auditLogs);
    }

    public String targetInput()        { return targetInput; }
    public long totalDurationMs()      { return totalDurationMs; }
    public void setTotalDurationMs(long ms) { this.totalDurationMs = ms; }

    public int totalScanned()          { return hostsMap.size(); }
    public int totalAlive()            { return getAliveHosts().size(); }

    public String toSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== IP / NETWORK SCAN RESULT: ").append(targetInput).append(" ===\n");
        sb.append("Total Targets Scanned: ").append(totalScanned())
          .append(" | Alive Hosts: ").append(totalAlive())
          .append(" | Duration: ").append(totalDurationMs).append("ms\n\n");

        for (IpHostEntry h : getAliveHosts()) {
            sb.append("• ").append(h.ip())
              .append(" (").append(h.hostname()).append(")")
              .append(" -> Open Ports: ").append(h.getPortsString())
              .append(" | Service: ").append(h.httpService())
              .append(" (").append(h.responseTimeMs()).append("ms)\n");
        }

        return sb.toString();
    }
}
