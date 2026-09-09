package com.sn1persecurity.silentchain.bapp.modules.recon;

import java.util.ArrayList;
import java.util.List;

/**
 * Detailed information about a discovered subdomain, including resolved IPs,
 * open ports, HTTP status, and web service title/server.
 */
public class SubdomainEntry {

    private final String subdomain;
    private final List<String> ips = new ArrayList<>();
    private final List<Integer> openPorts = new ArrayList<>();
    private volatile int httpStatus = 0;
    private volatile String pageTitle = "-";
    private volatile String serverHeader = "-";
    private volatile boolean alive = false;

    public SubdomainEntry(String subdomain) {
        this.subdomain = subdomain;
    }

    public String subdomain()               { return subdomain; }
    public List<String> ips()               { return ips; }
    public List<Integer> openPorts()        { return openPorts; }
    public int httpStatus()                 { return httpStatus; }
    public String pageTitle()               { return pageTitle; }
    public String serverHeader()            { return serverHeader; }
    public boolean isAlive()                { return alive; }

    public void addIp(String ip) {
        if (ip != null && !ip.isEmpty() && !ips.contains(ip)) {
            ips.add(ip);
            alive = true;
        }
    }

    public void addIps(List<String> newIps) {
        if (newIps != null) {
            for (String ip : newIps) addIp(ip);
        }
    }

    public void addOpenPort(int port) {
        if (!openPorts.contains(port)) {
            openPorts.add(port);
            alive = true;
        }
    }

    public void setHttpStatus(int httpStatus) {
        this.httpStatus = httpStatus;
        if (httpStatus > 0) alive = true;
    }

    public void setPageTitle(String pageTitle) {
        this.pageTitle = pageTitle != null && !pageTitle.isEmpty() ? pageTitle : "-";
    }

    public void setServerHeader(String serverHeader) {
        this.serverHeader = serverHeader != null && !serverHeader.isEmpty() ? serverHeader : "-";
    }

    public void setAlive(boolean alive) {
        this.alive = alive;
    }

    public String getIpsString() {
        return ips.isEmpty() ? "-" : String.join(", ", ips);
    }

    public String getPortsString() {
        if (openPorts.isEmpty()) return "-";
        List<String> s = new ArrayList<>();
        for (int p : openPorts) s.add(String.valueOf(p));
        return String.join(", ", s);
    }
}
