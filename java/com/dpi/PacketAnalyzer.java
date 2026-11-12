package com.dpi;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class PacketAnalyzer {
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public static void printPacketSummary(ParsedPacket pkt, int packetNum) {
        Instant instant = Instant.ofEpochSecond(pkt.timestampSec);
        String formattedTime = DATE_FORMATTER.format(instant) + String.format(".%06d", pkt.timestampUsec);

        System.out.println("\n========== Packet #" + packetNum + " ==========");
        System.out.println("Time: " + formattedTime);

        // Ethernet
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        System.out.printf("  EtherType:       0x%04x", pkt.etherType);
        if (pkt.etherType == PacketParser.ETHERTYPE_IPV4) {
            System.out.print(" (IPv4)");
        } else if (pkt.etherType == PacketParser.ETHERTYPE_IPV6) {
            System.out.print(" (IPv6)");
        } else if (pkt.etherType == PacketParser.ETHERTYPE_ARP) {
            System.out.print(" (ARP)");
        }
        System.out.println();

        // IP
        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }

        // TCP
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }

        // UDP
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
        }

        // Payload
        if (pkt.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");
            System.out.print("  Preview: ");
            int previewLen = Math.min(pkt.payloadLength, 32);
            for (int i = 0; i < previewLen; i++) {
                System.out.printf("%02x ", pkt.rawData[pkt.payloadOffset + i] & 0xFF);
            }
            if (pkt.payloadLength > 32) {
                System.out.print("...");
            }
            System.out.println();
        }
    }

    public static void printUsage(String programName) {
        System.out.println("Usage: java " + programName + " <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println("\nExample:");
        System.out.println("  java " + programName + " capture.pcap 10");
    }

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer (Java v1.0)    ");
        System.out.println("====================================\n");

        if (args.length < 1) {
            printUsage("com.dpi.PacketAnalyzer");
            System.exit(1);
        }

        String filename = args[0];
        int maxPackets = -1;
        if (args.length >= 2) {
            try {
                maxPackets = Integer.parseInt(args[1]);
            } catch (NumberFormatException ignored) {}
        }

        try (PcapReader reader = new PcapReader(filename)) {
            PcapGlobalHeader gh = reader.getGlobalHeader();
            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + gh.versionMajor() + "." + gh.versionMinor());
            System.out.println("  Snaplen: " + gh.snapLen() + " bytes");
            System.out.println("  Link type: " + gh.network() + (gh.network() == 1 ? " (Ethernet)" : ""));

            System.out.println("\n--- Reading packets ---");

            RawPacket raw;
            ParsedPacket parsed = new ParsedPacket();
            int packetCount = 0;
            int parseErrors = 0;

            while ((raw = reader.readNextPacket()) != null) {
                packetCount++;
                if (PacketParser.parse(raw, parsed)) {
                    printPacketSummary(parsed, packetCount);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    parseErrors++;
                }

                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }

            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.println("  Total packets read:  " + packetCount);
            System.out.println("  Parse errors:        " + parseErrors);
            System.out.println("====================================");

        } catch (IOException e) {
            System.err.println("Error reading PCAP: " + e.getMessage());
            System.exit(1);
        }
    }
}

