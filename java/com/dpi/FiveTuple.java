package com.dpi;

import java.util.Objects;

public record FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    public static int parseIp(String ipStr) {
        if (ipStr == null || ipStr.isEmpty()) return 0;
        String[] parts = ipStr.split("\\.");
        if (parts.length != 4) return 0;
        int result = 0;
        for (int i = 0; i < 4; i++) {
            int octet = Integer.parseInt(parts[i].trim());
            result |= ((octet & 0xFF) << (i * 8));
        }
        return result;
    }

    public static String formatIp(int ip) {
        return ((ip >> 0) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    public String srcIpStr() {
        return formatIp(srcIp);
    }

    public String dstIpStr() {
        return formatIp(dstIp);
    }

    public String protocolStr() {
        return protocol == 6 ? "TCP" : (protocol == 17 ? "UDP" : "Proto(" + protocol + ")");
    }

    @Override
    public String toString() {
        return srcIpStr() + ":" + srcPort + " -> " + dstIpStr() + ":" + dstPort + " (" + protocolStr() + ")";
    }

    @Override
    public int hashCode() {
        // Effective 5-tuple hash
        int h = 0;
        h ^= Integer.hashCode(srcIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(dstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(srcPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(dstPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof FiveTuple other)) return false;
        return srcIp == other.srcIp &&
               dstIp == other.dstIp &&
               srcPort == other.srcPort &&
               dstPort == other.dstPort &&
               protocol == other.protocol;
    }
}

