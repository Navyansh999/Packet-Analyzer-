package com.dpi;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PacketParser {
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    public static final int PROTOCOL_ICMP = 1;
    public static final int PROTOCOL_TCP  = 6;
    public static final int PROTOCOL_UDP  = 17;

    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        if (raw == null || raw.data == null) return false;

        parsed.hasIp = false;
        parsed.hasTcp = false;
        parsed.hasUdp = false;
        parsed.ipVersion = 0;
        parsed.srcIp = "";
        parsed.destIp = "";
        parsed.protocol = 0;
        parsed.ttl = 0;
        parsed.srcPort = 0;
        parsed.destPort = 0;
        parsed.tcpFlags = 0;
        parsed.seqNumber = 0;
        parsed.ackNumber = 0;
        parsed.payloadOffset = 0;
        parsed.payloadLength = 0;

        byte[] data = raw.data;
        int len = data.length;
        parsed.rawData = data;
        parsed.timestampSec = raw.tsSec;
        parsed.timestampUsec = raw.tsUsec;

        int offset = 0;

        // Ethernet (14 bytes)
        if (len < 14) return false;
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        parsed.etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
        offset = 14;

        // IPv4
        if (parsed.etherType == ETHERTYPE_IPV4) {
            if (len < offset + 20) return false;

            int versionIhl = data[offset] & 0xFF;
            parsed.ipVersion = (versionIhl >> 4) & 0x0F;
            int ihl = versionIhl & 0x0F;

            if (parsed.ipVersion != 4 || ihl < 5) return false;

            int ipHeaderLen = ihl * 4;
            if (len < offset + ipHeaderLen) return false;

            parsed.ttl = data[offset + 8] & 0xFF;
            parsed.protocol = data[offset + 9] & 0xFF;
            parsed.srcIp = ipToString(data, offset + 12);
            parsed.destIp = ipToString(data, offset + 16);
            parsed.hasIp = true;

            offset += ipHeaderLen;

            // Transport Layer
            if (parsed.protocol == PROTOCOL_TCP) {
                if (len < offset + 20) return false;

                parsed.srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                parsed.destPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);

                ByteBuffer bb = ByteBuffer.wrap(data, offset + 4, 8).order(ByteOrder.BIG_ENDIAN);
                parsed.seqNumber = Integer.toUnsignedLong(bb.getInt());
                parsed.ackNumber = Integer.toUnsignedLong(bb.getInt());

                int dataOffset = ((data[offset + 12] & 0xFF) >> 4) & 0x0F;
                int tcpHeaderLen = dataOffset * 4;
                if (tcpHeaderLen < 20 || len < offset + tcpHeaderLen) return false;

                parsed.tcpFlags = data[offset + 13] & 0xFF;
                parsed.hasTcp = true;
                offset += tcpHeaderLen;

            } else if (parsed.protocol == PROTOCOL_UDP) {
                if (len < offset + 8) return false;

                parsed.srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                parsed.destPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
                parsed.hasUdp = true;
                offset += 8;
            }
        }

        // Payload
        if (offset < len) {
            parsed.payloadOffset = offset;
            parsed.payloadLength = len - offset;
        } else {
            parsed.payloadOffset = len;
            parsed.payloadLength = 0;
        }

        return true;
    }

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." +
               (data[offset + 1] & 0xFF) + "." +
               (data[offset + 2] & 0xFF) + "." +
               (data[offset + 3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case PROTOCOL_TCP -> "TCP";
            case PROTOCOL_UDP -> "UDP";
            case PROTOCOL_ICMP -> "ICMP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_RST) != 0) sb.append("RST ");
        if ((flags & TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_URG) != 0) sb.append("URG ");
        String str = sb.toString().trim();
        return str.isEmpty() ? "none" : str;
    }
}
