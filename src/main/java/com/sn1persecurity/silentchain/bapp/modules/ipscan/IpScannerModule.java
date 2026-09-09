package com.sn1persecurity.silentchain.bapp.modules.ipscan;

import burp.api.montoya.MontoyaApi;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 100% Pure Java IP & Network Scanner module.
 * Supports Single IP, Comma-separated IPs, IP Ranges (192.168.1.1-50),
 * CIDR Subnets (192.168.1.0/24), Reverse DNS (PTR), Port Profiles, and HTTP banner grabbing.
 */
public class IpScannerModule {

    private final MontoyaApi api;
    private volatile boolean cancelled = false;

    public IpScannerModule(MontoyaApi api) {
        this.api = api;
    }

    public void cancel() {
        this.cancelled = true;
    }

    /**
     * Executes IP / Network scan with real-time logging and progress callbacks.
     */
    public IpScanResult runScan(String targetInput, List<Integer> ports, int threads, int timeoutMs,
                                Consumer<String> auditLogCallback, Consumer<IpHostEntry> hostDiscoveredCallback) {
        cancelled = false;
        long startTime = System.currentTimeMillis();
        IpScanResult result = new IpScanResult(targetInput);

        Consumer<String> logger = msg -> {
            result.addAuditLog(msg);
            if (auditLogCallback != null) auditLogCallback.accept(msg);
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("IP-SCAN: " + msg);
            }
        };

        logger.accept("⚡ Starting IP / Network Scanner for target: " + targetInput);
        logger.accept("⚙️ Config: " + threads + " threads | Timeout: " + timeoutMs + "ms | Ports: " + ports.size() + " ports selected");

        List<String> targetIps = parseTargetIps(targetInput, logger);
        if (targetIps.isEmpty()) {
            logger.accept("❌ No valid IP addresses or ranges resolved from input: " + targetInput);
            result.setTotalDurationMs(System.currentTimeMillis() - startTime);
            return result;
        }

        logger.accept("🎯 Total IP targets to audit: " + targetIps.size());

        ExecutorService executor = Executors.newFixedThreadPool(Math.max(1, Math.min(threads, 100)));

        for (String ip : targetIps) {
            if (cancelled) break;

            executor.submit(() -> {
                if (cancelled) return;
                IpHostEntry entry = result.getOrCreateHost(ip);

                // 1. PTR Reverse DNS Lookup
                try {
                    InetAddress addr = InetAddress.getByName(ip);
                    String hostName = addr.getCanonicalHostName();
                    if (hostName != null && !hostName.equalsIgnoreCase(ip)) {
                        entry.setHostname(hostName);
                    }
                } catch (Throwable ignored) {}

                // 2. Port Scanning
                boolean anyPortOpen = false;
                long bestPing = -1;

                for (int port : ports) {
                    if (cancelled) break;
                    long t0 = System.currentTimeMillis();
                    try (Socket socket = new Socket()) {
                        socket.connect(new InetSocketAddress(ip, port), timeoutMs);
                        long ping = System.currentTimeMillis() - t0;
                        if (bestPing < 0 || ping < bestPing) {
                            bestPing = ping;
                        }
                        entry.addOpenPort(port);
                        anyPortOpen = true;
                        logger.accept("[+] OPEN PORT: " + ip + ":" + port + " (" + getPortServiceName(port) + ") [" + ping + "ms]");

                        // 3. Web Service Banner Grabbing for HTTP/HTTPS ports
                        if (isHttpPort(port) && "-".equals(entry.httpService())) {
                            String banner = probeHttpBanner(ip, port, timeoutMs);
                            if (banner != null && !banner.isEmpty()) {
                                entry.setHttpService(banner);
                                logger.accept("[+] SERVICE DETECTED: " + ip + ":" + port + " -> " + banner);
                            }
                        }
                    } catch (Throwable ignored) {
                        // Port closed or filtered
                    }
                }

                if (anyPortOpen) {
                    entry.setAlive(true);
                    entry.setResponseTimeMs(bestPing);
                    if (hostDiscoveredCallback != null) {
                        hostDiscoveredCallback.accept(entry);
                    }
                }
            });
        }

        executor.shutdown();
        try {
            executor.awaitTermination(30, TimeUnit.MINUTES);
        } catch (InterruptedException ignored) {}

        long duration = System.currentTimeMillis() - startTime;
        result.setTotalDurationMs(duration);

        logger.accept("🏁 IP Scan " + (cancelled ? "CANCELLED" : "COMPLETED") + " in " + (duration / 1000.0) + "s. Alive Hosts: " + result.totalAlive() + " / " + result.totalScanned());
        return result;
    }

    /**
     * Parses IP, CIDR (e.g. 192.168.1.0/24), Ranges (192.168.1.1-50 or 10.0.0.1-10.0.0.20),
     * and Hostnames into a list of IPv4 addresses.
     */
    public List<String> parseTargetIps(String input, Consumer<String> log) {
        if (input == null || input.trim().isEmpty()) return Collections.emptyList();
        Set<String> ipSet = new LinkedHashSet<>();

        String[] tokens = input.split("[,;\\s]+");
        for (String token : tokens) {
            String trimmed = token.trim();
            if (trimmed.isEmpty()) continue;

            if (trimmed.contains("/")) {
                // CIDR notation (e.g. 192.168.1.0/24)
                parseCidr(trimmed, ipSet, log);
            } else if (trimmed.contains("-")) {
                // Range notation (e.g. 192.168.1.1-50 or 192.168.1.1-192.168.1.50)
                parseRange(trimmed, ipSet, log);
            } else if (isIpv4(trimmed)) {
                ipSet.add(trimmed);
            } else {
                // Hostname -> resolve to IPs
                try {
                    InetAddress[] addrs = InetAddress.getAllByName(trimmed);
                    for (InetAddress a : addrs) {
                        ipSet.add(a.getHostAddress());
                    }
                } catch (Throwable t) {
                    if (log != null) log.accept("[!] Warning: Unable to resolve hostname '" + trimmed + "': " + t.getMessage());
                }
            }
        }

        // Safeguard: Cap at 1024 IPs per scan session to prevent resource exhaustion
        List<String> result = new ArrayList<>(ipSet);
        if (result.size() > 1024) {
            if (log != null) log.accept("[!] Note: Capping IP list to first 1024 hosts for safety.");
            return result.subList(0, 1024);
        }
        return result;
    }

    private void parseCidr(String cidr, Set<String> ipSet, Consumer<String> log) {
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) return;
            String baseIp = parts[0].trim();
            int prefix = Integer.parseInt(parts[1].trim());

            if (prefix < 16 || prefix > 32) {
                if (log != null) log.accept("[!] Warning: Prefix /" + prefix + " is outside safe scan limit (/16 - /32).");
                return;
            }

            long ipLong = ipToLong(baseIp);
            long mask = prefix == 0 ? 0 : (-1L << (32 - prefix)) & 0xFFFFFFFFL;
            long network = ipLong & mask;
            long broadcast = network | (~mask & 0xFFFFFFFFL);

            // Add usable host IPs
            long start = (prefix >= 31) ? network : network + 1;
            long end = (prefix >= 31) ? broadcast : broadcast - 1;

            for (long cur = start; cur <= end; cur++) {
                ipSet.add(longToIp(cur));
                if (ipSet.size() >= 1024) break;
            }
        } catch (Throwable t) {
            if (log != null) log.accept("[!] Error parsing CIDR '" + cidr + "': " + t.getMessage());
        }
    }

    private void parseRange(String rangeStr, Set<String> ipSet, Consumer<String> log) {
        try {
            String[] parts = rangeStr.split("-");
            if (parts.length != 2) return;
            String startStr = parts[0].trim();
            String endStr = parts[1].trim();

            if (!isIpv4(startStr)) return;

            long startIp = ipToLong(startStr);
            long endIp;

            if (isIpv4(endStr)) {
                endIp = ipToLong(endStr);
            } else {
                // Short form: 192.168.1.1-50 -> last octet
                int lastOctet = Integer.parseInt(endStr);
                int lastDot = startStr.lastIndexOf('.');
                String prefix = startStr.substring(0, lastDot + 1);
                endIp = ipToLong(prefix + lastOctet);
            }

            if (startIp > endIp) {
                long tmp = startIp;
                startIp = endIp;
                endIp = tmp;
            }

            for (long cur = startIp; cur <= endIp; cur++) {
                ipSet.add(longToIp(cur));
                if (ipSet.size() >= 1024) break;
            }
        } catch (Throwable t) {
            if (log != null) log.accept("[!] Error parsing range '" + rangeStr + "': " + t.getMessage());
        }
    }

    private String probeHttpBanner(String ip, int port, int timeoutMs) {
        String[] schemes = (port == 443 || port == 8443) ? new String[]{"https://", "http://"} : new String[]{"http://", "https://"};
        for (String scheme : schemes) {
            try {
                URL url = new URI(scheme + ip + ":" + port + "/").toURL();
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) burpinho/3.2");
                conn.setConnectTimeout(timeoutMs);
                conn.setReadTimeout(timeoutMs);
                conn.setInstanceFollowRedirects(false);

                int code = conn.getResponseCode();
                String server = conn.getHeaderField("Server");
                if (server == null) server = "-";

                String title = "-";
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder body = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null && body.length() < 8000) {
                        body.append(line);
                    }
                    Matcher m = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE).matcher(body);
                    if (m.find()) {
                        title = m.group(1).trim().replaceAll("\\s+", " ");
                    }
                } catch (Throwable ignored) {}

                return "[" + code + "] Title: " + title + " | Server: " + server;
            } catch (Throwable ignored) {}
        }
        return null;
    }

    private static boolean isHttpPort(int port) {
        return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000 ||
               port == 8888 || port == 3000 || port == 5000 || port == 9000 || port == 9200;
    }

    private static boolean isIpv4(String s) {
        return s.matches("^(\\d{1,3}\\.){3}\\d{1,3}$");
    }

    private static long ipToLong(String ip) {
        String[] octets = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(octets[i]) << (24 - (8 * i)));
        }
        return result & 0xFFFFFFFFL;
    }

    private static String longToIp(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               (ip & 0xFF);
    }

    private static String getPortServiceName(int port) {
        return switch (port) {
            case 21 -> "FTP";
            case 22 -> "SSH";
            case 23 -> "Telnet";
            case 25 -> "SMTP";
            case 53 -> "DNS";
            case 80 -> "HTTP";
            case 110 -> "POP3";
            case 143 -> "IMAP";
            case 443 -> "HTTPS";
            case 445 -> "SMB";
            case 1433 -> "MSSQL";
            case 1521 -> "Oracle";
            case 3000 -> "Node/React";
            case 3306 -> "MySQL";
            case 3389 -> "RDP";
            case 5000 -> "Flask";
            case 5432 -> "PostgreSQL";
            case 6379 -> "Redis";
            case 8000 -> "HTTP-Alt";
            case 8080 -> "HTTP-Proxy";
            case 8443 -> "HTTPS-Alt";
            case 8888 -> "HTTP-Admin";
            case 9000 -> "FastCGI/Sonar";
            case 9200 -> "Elasticsearch";
            case 27017 -> "MongoDB";
            default -> "Port " + port;
        };
    }
}
