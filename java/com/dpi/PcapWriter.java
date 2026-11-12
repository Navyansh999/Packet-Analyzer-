package com.dpi;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapWriter implements AutoCloseable {
    private final OutputStream out;
    private final ByteOrder byteOrder;

    public PcapWriter(String filename, PcapGlobalHeader header, ByteOrder byteOrder) throws IOException {
        this.out = new BufferedOutputStream(new FileOutputStream(filename));
        this.byteOrder = byteOrder != null ? byteOrder : ByteOrder.LITTLE_ENDIAN;
        writeGlobalHeader(header);
    }

    private void writeGlobalHeader(PcapGlobalHeader header) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(24).order(byteOrder);
        buf.putInt((int) PcapGlobalHeader.PCAP_MAGIC_NATIVE);
        buf.putShort((short) (header != null ? header.versionMajor() : 2));
        buf.putShort((short) (header != null ? header.versionMinor() : 4));
        buf.putInt(header != null ? header.thisZone() : 0);
        buf.putInt(header != null ? (int) header.sigFigs() : 0);
        buf.putInt(header != null ? (int) header.snapLen() : 65535);
        buf.putInt(header != null ? (int) header.network() : 1);

        out.write(buf.array());
    }

    public synchronized void writePacket(long tsSec, long tsUsec, byte[] data) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(16).order(byteOrder);
        buf.putInt((int) tsSec);
        buf.putInt((int) tsUsec);
        buf.putInt(data.length);
        buf.putInt(data.length);

        out.write(buf.array());
        out.write(data);
    }

    @Override
    public void close() throws IOException {
        out.flush();
        out.close();
    }
}

