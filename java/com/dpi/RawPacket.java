package com.dpi;

public class RawPacket {
    public long tsSec;
    public long tsUsec;
    public int inclLen;
    public int origLen;
    public byte[] data;

    public RawPacket() {}

    public RawPacket(long tsSec, long tsUsec, int inclLen, int origLen, byte[] data) {
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
        this.inclLen = inclLen;
        this.origLen = origLen;
        this.data = data;
    }
}

