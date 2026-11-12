package com.dpi;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader implements AutoCloseable {
    private final InputStream in;
    private final String filename;
    private PcapGlobalHeader globalHeader;
    private ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;

    public PcapReader(String filename) throws IOException {
        this.filename = filename;
        this.in = new BufferedInputStream(new FileInputStream(filename));
        readGlobalHeader();
    }

    private void readGlobalHeader() throws IOException {
        byte[] headerBytes = in.readNBytes(24);
        if (headerBytes.length < 24) {
            throw new IOException("Could not read PCAP global header from: " + filename);
        }

        long valLE = (headerBytes[0] & 0xFFL) | ((headerBytes[1] & 0xFFL) << 8) |
                     ((headerBytes[2] & 0xFFL) << 16) | ((headerBytes[3] & 0xFFL) << 24);
        long valBE = ((headerBytes[0] & 0xFFL) << 24) | ((headerBytes[1] & 0xFFL) << 16) |
                     ((headerBytes[2] & 0xFFL) << 8) | (headerBytes[3] & 0xFFL);

        if (valLE == PcapGlobalHeader.PCAP_MAGIC_NATIVE) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else if (valBE == PcapGlobalHeader.PCAP_MAGIC_NATIVE) {
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else {
            throw new IOException(String.format("Invalid PCAP magic number: 0x%08X", valBE));
        }

        ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(byteOrder);
        buf.getInt(); // skip magic
        int versionMajor = Short.toUnsignedInt(buf.getShort());
        int versionMinor = Short.toUnsignedInt(buf.getShort());
        int thisZone = buf.getInt();
        long sigFigs = Integer.toUnsignedLong(buf.getInt());
        long snapLen = Integer.toUnsignedLong(buf.getInt());
        long network = Integer.toUnsignedLong(buf.getInt());

        this.globalHeader = new PcapGlobalHeader(
            valLE == PcapGlobalHeader.PCAP_MAGIC_NATIVE ? valLE : valBE,
            versionMajor, versionMinor, thisZone, sigFigs, snapLen, network
        );
    }

    public RawPacket readNextPacket() throws IOException {
        byte[] headerBytes = in.readNBytes(16);
        if (headerBytes.length == 0) {
            return null; // EOF
        }
        if (headerBytes.length < 16) {
            throw new EOFException("Incomplete packet header");
        }

        ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(byteOrder);
        long tsSec = Integer.toUnsignedLong(buf.getInt());
        long tsUsec = Integer.toUnsignedLong(buf.getInt());
        int inclLen = buf.getInt();
        int origLen = buf.getInt();

        if (inclLen < 0 || inclLen > 65535) {
            throw new IOException("Invalid packet length: " + inclLen);
        }

        byte[] packetData = in.readNBytes(inclLen);
        if (packetData.length < inclLen) {
            throw new EOFException("Incomplete packet data");
        }

        return new RawPacket(tsSec, tsUsec, inclLen, origLen, packetData);
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public ByteOrder getByteOrder() {
        return byteOrder;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}

