package com.sn1persecurity.silentchain.bapp.modules.ipscan;

import java.util.ArrayList;
import java.util.List;

/**
 * Information about a scanned IP host (Reverse DNS PTR, Open Ports, HTTP banners).
 */
public class IpHostEntry {

    private final String ip;
    private volatile String hostname = "-";
    private final List<Integer> openPorts = new ArrayList<>();
    private volatile String httpService = "-";
    private volatile long responseTimeMs = -1;
    private volatile boolean alive = false;

    public IpHostEntry(String ip) {
        this.ip = ip;
    }

    public String ip()                     { return ip; }
    public String hostname()               { return hostname; }
    public List<Integer> openPorts()      { return openPorts; }
    public String httpService()            { return httpService; }
    public long responseTimeMs()           { return responseTimeMs; }
    public boolean isAlive()               { return alive; }

    public void setHostname(String hostname) {
        this.hostname = hostname != null && !hostname.isEmpty() ? hostname : "-";
    }

    public void addOpenPort(int port) {
        if (!openPorts.contains(port)) {
            openPorts.add(port);
            alive = true;
        }
    }

    public void setHttpService(String httpService) {
        this.httpService = httpService != null && !httpService.isEmpty() ? httpService : "-";
        alive = true;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public void setAlive(boolean alive) {
        this.alive = alive;
    }

    public String getPortsString() {
        if (openPorts.isEmpty()) return "-";
        List<String> s = new ArrayList<>();
        for (int p : openPorts) s.add(String.valueOf(p));
        return String.join(", ", s);
    }
}
