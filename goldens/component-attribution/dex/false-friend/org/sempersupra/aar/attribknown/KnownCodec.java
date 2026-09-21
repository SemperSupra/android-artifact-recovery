package org.sempersupra.aar.attribknown;

public final class KnownCodec {
    private KnownCodec() {}

    public static int fold(byte[] data) {
        int acc = 0;
        for (int i = 0; i < data.length; i++) {
            acc += (data[i] & 0xff) * (i + 3);
        }
        return acc;
    }

    public static String normalize(String value) {
        return new StringBuilder(value.trim()).reverse().toString();
    }
}
