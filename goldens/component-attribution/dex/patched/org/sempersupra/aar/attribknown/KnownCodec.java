package org.sempersupra.aar.attribknown;

public final class KnownCodec {
    private KnownCodec() {}

    public static int fold(byte[] data) {
        int acc = 0x13579bdf;
        for (byte b : data) {
            acc = Integer.rotateLeft(acc ^ (b & 0xff), 5) + 0x1020304;
        }
        return acc ^ 0x10001;
    }

    public static String normalize(String value) {
        return value.trim().toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
    }
}
