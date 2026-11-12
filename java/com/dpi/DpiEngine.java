package com.dpi;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class DpiEngine {

    public static class Config {
        public int numLbs = 2;
        public int fpsPerLb = 2;
    }

    public static class FlowEntry {
        public FiveTuple tuple;
        public AppType appType = AppType.UNKNOWN;
        public String sni = "";
        public long packets = 0;
        public long bytes = 0;
        public boolean blocked = false;
        public boolean classified = false;
    }

    public static class PacketJob {
        public long id;
        public long tsSec;
        public long tsUsec;
        public FiveTuple tuple;
        public byte[] data;
        public int payloadOffset;
        public int payloadLength;
        public int tcpFlags;
        public boolean isEof = false;

        public static PacketJob eof() {
            PacketJob p = new PacketJob();
            p.isEof = true;
            return p;
        }
    }

    public static class Stats {
        public final AtomicLong totalPackets = new AtomicLong();
        public final AtomicLong totalBytes = new AtomicLong();
        public final AtomicLong forwarded = new AtomicLong();
        public final AtomicLong dropped = new AtomicLong();
        public final AtomicLong tcpPackets = new AtomicLong();
        public final AtomicLong udpPackets = new AtomicLong();

        public final ConcurrentHashMap<AppType, AtomicLong> appCounts = new ConcurrentHashMap<>();
        public final ConcurrentHashMap<String, AppType> detectedSnis = new ConcurrentHashMap<>();

        public void recordApp(AppType app, String sni) {
            appCounts.computeIfAbsent(app, k -> new AtomicLong()).incrementAndGet();
            if (sni != null && !sni.isEmpty()) {
                detectedSnis.put(sni, app);
            }
        }
    }

    private final Config config;
    private final Rules rules = new Rules();
    private final Stats stats = new Stats();

    public DpiEngine(Config config) {
        this.config = config != null ? config : new Config();
    }

    public void blockIp(String ip) { rules.blockIp(ip); }
    public void blockApp(String app) { rules.blockApp(app); }
    public void blockDomain(String domain) { rules.blockDomain(domain); }

    public boolean process(String inputFile, String outputFile) {
        int totalFps = config.numLbs * config.fpsPerLb;

        System.out.println();
        System.out.println("+==============================================================+");
        System.out.println("|             DPI ENGINE (Java Multi-threaded)                 |");
        System.out.println("+==============================================================+");
        System.out.printf("| Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d     |%n",
                config.numLbs, config.fpsPerLb, totalFps);
        System.out.println("+==============================================================+\n");

        PcapReader reader;
        PcapWriter writer;
        try {
            reader = new PcapReader(inputFile);
            PcapGlobalHeader gh = reader.getGlobalHeader();
            System.out.println("Opened PCAP file: " + inputFile);
            System.out.println("  Version: " + gh.versionMajor() + "." + gh.versionMinor());
            System.out.println("  Snaplen: " + gh.snapLen() + " bytes");
            System.out.println("  Link type: " + gh.network() + (gh.network() == 1 ? " (Ethernet)" : ""));
            writer = new PcapWriter(outputFile, gh, reader.getByteOrder());
        } catch (IOException e) {
            System.err.println("I/O Error: " + e.getMessage());
            return false;
        }

        // Queues and threads
        BlockingQueue<PacketJob> outputQueue = new ArrayBlockingQueue<>(10000);
        List<BlockingQueue<PacketJob>> fpQueues = new ArrayList<>();
        List<AtomicLong> fpProcessed = new ArrayList<>();
        List<Thread> fpThreads = new ArrayList<>();

        // Create Fast Path workers
        for (int i = 0; i < totalFps; i++) {
            BlockingQueue<PacketJob> fpQueue = new ArrayBlockingQueue<>(5000);
            fpQueues.add(fpQueue);
            AtomicLong processed = new AtomicLong();
            fpProcessed.add(processed);

            int fpId = i;
            Thread t = new Thread(() -> runFastPath(fpId, fpQueue, outputQueue, processed));
            t.setName("FastPath-" + fpId);
            fpThreads.add(t);
            t.start();
        }

        // Create Load Balancer workers
        List<BlockingQueue<PacketJob>> lbQueues = new ArrayList<>();
        List<AtomicLong> lbDispatched = new ArrayList<>();
        List<Thread> lbThreads = new ArrayList<>();

        for (int lb = 0; lb < config.numLbs; lb++) {
            BlockingQueue<PacketJob> lbQueue = new ArrayBlockingQueue<>(5000);
            lbQueues.add(lbQueue);
            AtomicLong dispatched = new AtomicLong();
            lbDispatched.add(dispatched);

            int startFp = lb * config.fpsPerLb;
            List<BlockingQueue<PacketJob>> targetFps = new ArrayList<>();
            for (int k = 0; k < config.fpsPerLb; k++) {
                targetFps.add(fpQueues.get(startFp + k));
            }

            int lbId = lb;
            Thread t = new Thread(() -> runLoadBalancer(lbId, lbQueue, targetFps, dispatched));
            t.setName("LoadBalancer-" + lbId);
            lbThreads.add(t);
            t.start();
        }

        // Writer Thread
        CountDownLatch writerDone = new CountDownLatch(1);
        Thread writerThread = new Thread(() -> {
            try {
                while (true) {
                    PacketJob job = outputQueue.take();
                    if (job.isEof) break;
                    writer.writePacket(job.tsSec, job.tsUsec, job.data);
                }
            } catch (Exception e) {
                System.err.println("Writer error: " + e.getMessage());
            } finally {
                try {
                    writer.close();
                } catch (IOException ignored) {}
                writerDone.countDown();
            }
        });
        writerThread.setName("OutputWriter");
        writerThread.start();

        // Main Reader Loop
        System.out.println("[Reader] Processing packets...");
        long packetCount = 0;
        try {
            RawPacket raw;
            ParsedPacket parsed = new ParsedPacket();
            while ((raw = reader.readNextPacket()) != null) {
                if (!PacketParser.parse(raw, parsed)) continue;
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

                PacketJob job = new PacketJob();
                job.id = packetCount++;
                job.tsSec = raw.tsSec;
                job.tsUsec = raw.tsUsec;
                job.data = raw.data;
                job.tcpFlags = parsed.tcpFlags;
                job.payloadOffset = parsed.payloadOffset;
                job.payloadLength = parsed.payloadLength;

                job.tuple = new FiveTuple(
                    FiveTuple.parseIp(parsed.srcIp),
                    FiveTuple.parseIp(parsed.destIp),
                    parsed.srcPort,
                    parsed.destPort,
                    parsed.protocol
                );

                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);
                if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
                else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

                // Dispatch to Load Balancer via 5-tuple hash
                int lbIdx = Math.floorMod(job.tuple.hashCode(), config.numLbs);
                lbQueues.get(lbIdx).put(job);
            }
            reader.close();
        } catch (Exception e) {
            System.err.println("Reader error: " + e.getMessage());
        }

        System.out.println("[Reader] Done reading " + packetCount + " packets");

        // Drain pipeline: Send EOF to LBs
        try {
            for (BlockingQueue<PacketJob> lbq : lbQueues) {
                lbq.put(PacketJob.eof());
            }
            for (Thread t : lbThreads) {
                t.join();
            }

            // LBs have stopped and sent EOF to their respective FPs
            for (Thread t : fpThreads) {
                t.join();
            }

            // All FPs have stopped, send EOF to writer
            outputQueue.put(PacketJob.eof());
            writerDone.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        printReport(lbDispatched, fpProcessed);
        System.out.println("\nOutput written to: " + outputFile);
        return true;
    }

    private void runLoadBalancer(int id, BlockingQueue<PacketJob> inQueue,
                                 List<BlockingQueue<PacketJob>> targetFps, AtomicLong dispatched) {
        try {
            while (true) {
                PacketJob job = inQueue.take();
                if (job.isEof) {
                    for (BlockingQueue<PacketJob> fpq : targetFps) {
                        fpq.put(PacketJob.eof());
                    }
                    break;
                }
                int fpIdx = Math.floorMod(job.tuple.hashCode(), targetFps.size());
                targetFps.get(fpIdx).put(job);
                dispatched.incrementAndGet();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void runFastPath(int id, BlockingQueue<PacketJob> inQueue,
                             BlockingQueue<PacketJob> outQueue, AtomicLong processed) {
        Map<FiveTuple, FlowEntry> flows = new HashMap<>();
        try {
            while (true) {
                PacketJob job = inQueue.take();
                if (job.isEof) break;

                processed.incrementAndGet();

                FlowEntry flow = flows.computeIfAbsent(job.tuple, t -> {
                    FlowEntry entry = new FlowEntry();
                    entry.tuple = t;
                    return entry;
                });

                flow.packets++;
                flow.bytes += job.data.length;

                if (!flow.classified) {
                    classifyFlow(job, flow);
                }

                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(job.tuple.srcIp(), flow.appType, flow.sni);
                }

                stats.recordApp(flow.appType, flow.sni);

                if (flow.blocked) {
                    stats.dropped.incrementAndGet();
                } else {
                    stats.forwarded.incrementAndGet();
                    outQueue.put(job);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void classifyFlow(PacketJob job, FlowEntry flow) {
        // HTTPS SNI extraction
        if (job.tuple.dstPort() == 443 && job.payloadLength > 5) {
            String sni = SNIExtractor.extractSNI(job.data, job.payloadOffset, job.payloadLength);
            if (sni != null) {
                flow.sni = sni;
                flow.appType = AppType.fromSni(sni);
                flow.classified = true;
                return;
            }
        }

        // HTTP Host extraction
        if (job.tuple.dstPort() == 80 && job.payloadLength > 10) {
            String host = SNIExtractor.extractHttpHost(job.data, job.payloadOffset, job.payloadLength);
            if (host != null) {
                flow.sni = host;
                flow.appType = AppType.fromSni(host);
                flow.classified = true;
                return;
            }
        }

        // DNS
        if (job.tuple.dstPort() == 53 || job.tuple.srcPort() == 53) {
            flow.appType = AppType.DNS;
            flow.classified = true;
            return;
        }

        // Fallbacks
        if (job.tuple.dstPort() == 443) {
            flow.appType = AppType.HTTPS;
        } else if (job.tuple.dstPort() == 80) {
            flow.appType = AppType.HTTP;
        }
    }

    private void printReport(List<AtomicLong> lbDispatched, List<AtomicLong> fpProcessed) {
        long total = stats.totalPackets.get();
        System.out.println("\n+==============================================================+");
        System.out.println("|                      PROCESSING REPORT                        |");
        System.out.println("+==============================================================+");
        System.out.printf("| Total Packets:      %12d                           |%n", total);
        System.out.printf("| Total Bytes:        %12d                           |%n", stats.totalBytes.get());
        System.out.printf("| TCP Packets:        %12d                           |%n", stats.tcpPackets.get());
        System.out.printf("| UDP Packets:        %12d                           |%n", stats.udpPackets.get());
        System.out.println("+==============================================================+");
        System.out.printf("| Forwarded:          %12d                           |%n", stats.forwarded.get());
        System.out.printf("| Dropped:            %12d                           |%n", stats.dropped.get());
        System.out.println("+==============================================================+");
        System.out.println("| THREAD STATISTICS                                             |");

        for (int i = 0; i < lbDispatched.size(); i++) {
            System.out.printf("|   LB%d dispatched:   %12d                           |%n", i, lbDispatched.get(i).get());
        }
        for (int i = 0; i < fpProcessed.size(); i++) {
            System.out.printf("|   FP%d processed:    %12d                           |%n", i, fpProcessed.get(i).get());
        }

        System.out.println("+==============================================================+");
        System.out.println("|                   APPLICATION BREAKDOWN                       |");
        System.out.println("+==============================================================+");

        List<Map.Entry<AppType, AtomicLong>> appList = new ArrayList<>(stats.appCounts.entrySet());
        appList.sort((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()));

        for (Map.Entry<AppType, AtomicLong> entry : appList) {
            long count = entry.getValue().get();
            double pct = total > 0 ? (100.0 * count / total) : 0.0;
            int barCount = (int) (pct / 5.0);
            String bar = "#".repeat(Math.max(0, barCount));

            System.out.printf("| %-15s %8d %5.1f%% %-20s  |%n",
                    entry.getKey().getDisplayName(), count, pct, bar);
        }

        System.out.println("+==============================================================+");

        if (!stats.detectedSnis.isEmpty()) {
            System.out.println("\n[Detected Domains/SNIs]");
            List<Map.Entry<String, AppType>> snis = new ArrayList<>(stats.detectedSnis.entrySet());
            snis.sort(Map.Entry.comparingByKey());
            for (Map.Entry<String, AppType> entry : snis) {
                System.out.println("  - " + entry.getKey() + " -> " + entry.getValue().getDisplayName());
            }
        }
    }

    public static void printUsage() {
        System.out.println("""
            DPI Engine (Java Edition) - Multi-threaded Deep Packet Inspection
            ==================================================================

            Usage: java com.dpi.DpiEngine <input.pcap> <output.pcap> [options]

            Options:
              --block-ip <ip>        Block source IP (e.g. 192.168.1.50)
              --block-app <app>      Block application (YouTube, Facebook, etc.)
              --block-domain <dom>   Block domain substring (e.g. twitter.com)
              --lbs <n>              Number of load balancer threads (default: 2)
              --fps <n>              FP threads per LB (default: 2)

            Example:
              java com.dpi.DpiEngine test_dpi.pcap filtered.pcap --block-app YouTube
            """);
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String input = args[0];
        String output = args[1];

        Config cfg = new Config();
        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                blockDomains.add(args[++i]);
            } else if (arg.equals("--lbs") && i + 1 < args.length) {
                cfg.numLbs = Integer.parseInt(args[++i]);
            } else if (arg.equals("--fps") && i + 1 < args.length) {
                cfg.fpsPerLb = Integer.parseInt(args[++i]);
            }
        }

        DpiEngine engine = new DpiEngine(cfg);
        for (String ip : blockIps) engine.blockIp(ip);
        for (String app : blockApps) engine.blockApp(app);
        for (String dom : blockDomains) engine.blockDomain(dom);

        boolean success = engine.process(input, output);
        if (!success) {
            System.exit(1);
        }
    }
}
