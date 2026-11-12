package com.dpi;

import java.nio.charset.StandardCharsets;

public class SNIExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    public static int readUint24BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 16) |
               ((data[offset + 1] & 0xFF) << 8) |
               (data[offset + 2] & 0xFF);
    }

    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        if (length < 9 || payload.length < offset + length) return false;

        // Content type 0x16 = Handshake
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        // TLS Version 0x0300 - 0x0304
        int version = readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;

        // Record length
        int recordLength = readUint16BE(payload, offset + 3);
        if (recordLength > length - 5) return false;

        // Handshake type 0x01 = Client Hello
        return (payload[offset + 5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    public static String extractSNI(byte[] payload, int offset, int length) {
        if (!isTLSClientHello(payload, offset, length)) {
            return null;
        }

        int pos = offset + 5; // skip TLS record header

        // Skip handshake header (1 byte type + 3 bytes length)
        if (pos + 4 > offset + length) return null;
        pos += 4;

        // Client version (2 bytes) + Random (32 bytes)
        pos += 2 + 32;
        if (pos >= offset + length) return null;

        // Session ID
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;
        if (pos + 2 > offset + length) return null;

        // Cipher suites
        int cipherSuitesLen = readUint16BE(payload, pos);
        pos += 2 + cipherSuitesLen;
        if (pos >= offset + length) return null;

        // Compression methods
        int compMethodsLen = payload[pos] & 0xFF;
        pos += 1 + compMethodsLen;
        if (pos + 2 > offset + length) return null;

        // Extensions
        int extensionsLen = readUint16BE(payload, pos);
        pos += 2;

        int extensionsEnd = Math.min(pos + extensionsLen, offset + length);

        while (pos + 4 <= extensionsEnd) {
            int extType = readUint16BE(payload, pos);
            int extLen = readUint16BE(payload, pos + 2);
            pos += 4;

            if (pos + extLen > extensionsEnd) break;

            if (extType == EXTENSION_SNI) {
                if (extLen < 5) break;

                int sniListLen = readUint16BE(payload, pos);
                if (sniListLen < 3) break;

                int sniType = payload[pos + 2] & 0xFF;
                int sniLen = readUint16BE(payload, pos + 3);

                if (sniType != SNI_TYPE_HOSTNAME || sniLen > extLen - 5) break;

                return new String(payload, pos + 5, sniLen, StandardCharsets.UTF_8);
            }

            pos += extLen;
        }

        return null;
    }

    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        if (length < 4 || payload.length < offset + length) return false;
        String prefix = new String(payload, offset, Math.min(length, 4), StandardCharsets.US_ASCII);
        return prefix.equals("GET ") || prefix.equals("POST") || prefix.equals("PUT ") ||
               prefix.equals("HEAD") || prefix.equals("DELE") || prefix.equals("PATC") ||
               prefix.equals("OPTI");
    }

    public static String extractHttpHost(byte[] payload, int offset, int length) {
        if (!isHTTPRequest(payload, offset, length)) return null;

        int endLimit = offset + length;
        for (int i = offset; i + 6 < endLimit; i++) {
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                (payload[i+1] == 'o' || payload[i+1] == 'O') &&
                (payload[i+2] == 's' || payload[i+2] == 'S') &&
                (payload[i+3] == 't' || payload[i+3] == 'T') &&
                payload[i+4] == ':') {

                int start = i + 5;
                while (start < endLimit && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                int end = start;
                while (end < endLimit && payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }

                if (end > start) {
                    String host = new String(payload, start, end - start, StandardCharsets.US_ASCII).trim();
                    int colon = host.indexOf(':');
                    if (colon != -1) {
                        host = host.substring(0, colon);
                    }
                    return host;
                }
            }
        }
        return null;
    }

    public static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (length < 12 || payload.length < offset + length) return false;
        // QR bit (byte 2, bit 7) - should be 0 for query
        if ((payload[offset + 2] & 0x80) != 0) return false;
        // QDCOUNT (bytes 4-5) - should be > 0
        int qdcount = readUint16BE(payload, offset + 4);
        return qdcount > 0;
    }

    public static String extractDnsQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length)) return null;

        int pos = offset + 12;
        int endLimit = offset + length;
        StringBuilder domain = new StringBuilder();

        while (pos < endLimit) {
            int labelLen = payload[pos] & 0xFF;
            if (labelLen == 0) break;
            if (labelLen > 63) break; // pointer or invalid

            pos++;
            if (pos + labelLen > endLimit) break;

            if (!domain.isEmpty()) {
                domain.append('.');
            }
            domain.append(new String(payload, pos, labelLen, StandardCharsets.US_ASCII));
            pos += labelLen;
        }

        return domain.isEmpty() ? null : domain.toString();
    }
}

