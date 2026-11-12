package com.dpi;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Rules {
    private final Set<Integer> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final List<String> blockedDomains = Collections.synchronizedList(new ArrayList<>());

    public void blockIp(String ipStr) {
        int ip = FiveTuple.parseIp(ipStr);
        blockedIps.add(ip);
        System.out.println("[Rules] Blocked IP: " + ipStr);
    }

    public void blockApp(String appName) {
        AppType app = AppType.fromDisplayName(appName);
        if (app != AppType.UNKNOWN) {
            blockedApps.add(app);
            System.out.println("[Rules] Blocked app: " + appName);
        } else {
            System.err.println("[Rules] Unknown app: " + appName);
        }
    }

    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    public boolean isBlocked(int srcIp, AppType app, String sni) {
        if (blockedIps.contains(srcIp)) return true;
        if (app != null && blockedApps.contains(app)) return true;
        if (sni != null && !sni.isEmpty()) {
            String lowerSni = sni.toLowerCase();
            synchronized (blockedDomains) {
                for (String dom : blockedDomains) {
                    if (lowerSni.contains(dom)) return true;
                }
            }
        }
        return false;
    }
}

