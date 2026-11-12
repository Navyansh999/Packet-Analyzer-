# Java DPI Engine & Packet Analyzer

A 100% pure Java port of the Deep Packet Inspection (DPI) and Packet Analyzer engine.
Requires **no external libraries** (uses standard Java SE standard library `java.nio`, `java.io`, `java.util.concurrent`).

---

## Features

- **PCAP Reader & Writer**: Reads and writes standard PCAP packet capture files, auto-detecting native or swapped byte order.
- **Protocol Decoding**: Ethernet, IPv4, TCP (with flags and sequence numbers), UDP, and payload inspection.
- **Deep Packet Inspection (DPI)**:
  - **TLS SNI Extraction**: Inspects TLS Client Hello handshake packets to extract server names without decryption.
  - **HTTP Host Extraction**: Inspects plaintext HTTP request headers.
  - **DNS Query Extraction**: Inspects DNS queries for requested domain names.
  - **Application Classifier**: Categorizes traffic into YouTube, Google, Facebook, Instagram, Twitter/X, Netflix, Amazon, Apple, Microsoft, Spotify, Discord, Telegram, TikTok, Zoom, GitHub, Cloudflare, etc.
- **Multi-threaded Pipeline**:
  - Reader Thread -> Load Balancers (5-tuple hashing) -> Fast Path workers (flow tracking & rule evaluation) -> Output PCAP Writer.
- **Traffic Filtering & Blocking**: Block traffic by source IP, application name, or domain substring.

---

## Project Structure

```
d:/apps/Packet_analyzer/java/
├── build.bat                 # 1-click build script
├── README.md                 # Documentation
└── com/dpi/
    ├── AppType.java          # Supported application types and SNI matcher
    ├── FiveTuple.java        # 5-tuple connection identifier (IPs, ports, proto)
    ├── RawPacket.java        # Raw PCAP packet data and timestamps
    ├── ParsedPacket.java     # Decoded Ethernet/IP/TCP/UDP packet metadata
    ├── PcapGlobalHeader.java # PCAP file header representation
    ├── PcapReader.java       # Binary PCAP parser
    ├── PcapWriter.java       # Binary PCAP generator
    ├── PacketParser.java     # Layer 2, 3, 4 protocol decoders
    ├── SNIExtractor.java     # TLS Client Hello SNI, HTTP Host, and DNS parser
    ├── Rules.java            # IP, domain, and application blocking rules
    ├── DpiEngine.java        # Multi-threaded DPI processing engine & CLI
    └── PacketAnalyzer.java   # Detailed packet inspector CLI
```

---

## How to Build and Run

### 1. Build

```powershell
cd d:\apps\Packet_analyzer\java
javac com\dpi\*.java
# Or simply run:
.\build.bat
```

### 2. Run the Multi-Threaded DPI Engine

```powershell
cd d:\apps\Packet_analyzer\java

# Basic analysis and write filtered PCAP
java com.dpi.DpiEngine ..\test_dpi.pcap output_java.pcap

# With blocking rules
java com.dpi.DpiEngine ..\test_dpi.pcap output_java.pcap --block-app YouTube --block-domain twitter.com --block-ip 192.168.1.50
```

### 3. Run the Detailed Packet Analyzer

```powershell
cd d:\apps\Packet_analyzer\java

# Inspect all packets
java com.dpi.PacketAnalyzer ..\test_dpi.pcap

# Inspect only the first 5 packets
java com.dpi.PacketAnalyzer ..\test_dpi.pcap 5
```

