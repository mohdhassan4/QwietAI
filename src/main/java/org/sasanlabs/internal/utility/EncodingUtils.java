package org.sasanlabs.internal.utility;

import java.util.Base64;

public class EncodingUtils {
    public static String bytesToHex(byte[] data) {
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte value : data) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high == -1 || low == -1) {
                throw new IllegalArgumentException("Invalid hex character at position " + (i * 2));
            }
            result[i] = (byte) ((high << 4) | low);
        }
        return result;
    }

    public static String encodeBase64(String rawText) {
        return Base64.getEncoder().encodeToString(rawText.getBytes());
    }
}
