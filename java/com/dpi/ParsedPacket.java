package com.dpi;

public class ParsedPacket {
    public long timestampSec;
    public long timestampUsec;

    // Ethernet
    public String srcMac = "";
    public String destMac = "";
    public int etherType;

    // IP
    public boolean hasIp = false;
    public int ipVersion = 0;
    public String srcIp = "";
    public String destIp = "";
    public int protocol = 0; // 6 = TCP, 17 = UDP, 1 = ICMP
    public int ttl = 0;

    // Transport
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort = 0;
    public int destPort = 0;

    // TCP specific
    public int tcpFlags = 0;
    public long seqNumber = 0;
    public long ackNumber = 0;

    // Payload
    public int payloadOffset = 0;
    public int payloadLength = 0;
    public byte[] rawData;

    public byte[] getPayload() {
        if (rawData == null || payloadLength <= 0 || payloadOffset >= rawData.length) {
            return new byte[0];
        }
        byte[] payload = new byte[payloadLength];
        System.arraycopy(rawData, payloadOffset, payload, 0, payloadLength);
        return payload;
    }
}

