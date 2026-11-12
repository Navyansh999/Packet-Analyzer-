package com.dpi;

public record PcapGlobalHeader(
    long magicNumber,
    int versionMajor,
    int versionMinor,
    int thisZone,
    long sigFigs,
    long snapLen,
    long network
) {
    public static final long PCAP_MAGIC_NATIVE = 0xa1b2c3d4L;
    public static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;
}

