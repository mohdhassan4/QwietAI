package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class to validate URLs against SSRF attacks. Blocks requests to internal/private IP
 * ranges, metadata endpoints, and non-HTTP(S) schemes.
 */
public final class UrlSafetyValidator {

    private UrlSafetyValidator() {}

    /**
     * Validates that the given URL is safe to request (not targeting internal resources).
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe, false if it targets a blocked destination
     */
    public static boolean isSafeUrl(String urlString) {
        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            return false;
        }

        String scheme = url.getProtocol();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Strip IPv6 brackets if present
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                if (isBlockedAddress(addr)) {
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            // Cannot resolve host - block to be safe
            return false;
        }

        return true;
    }

    private static boolean isBlockedAddress(InetAddress addr) {
        return addr.isLoopbackAddress()
                || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress()
                || addr.isAnyLocalAddress()
                || addr.isMulticastAddress()
                || isUniqueLocalIpv6(addr)
                || isMetadataAddress(addr);
    }

    private static boolean isUniqueLocalIpv6(InetAddress addr) {
        // fd00::/8 unique-local IPv6
        byte[] raw = addr.getAddress();
        return raw.length == 16 && (raw[0] & 0xFF) == 0xFD;
    }

    private static boolean isMetadataAddress(InetAddress addr) {
        // Cloud metadata endpoints: 169.254.169.254, 169.254.170.2
        byte[] raw = addr.getAddress();
        if (raw.length == 4) {
            int b0 = raw[0] & 0xFF;
            int b1 = raw[1] & 0xFF;
            int b2 = raw[2] & 0xFF;
            int b3 = raw[3] & 0xFF;
            if (b0 == 169 && b1 == 254) {
                if ((b2 == 169 && b3 == 254) || (b2 == 170 && b3 == 2)) {
                    return true;
                }
            }
        }
        // IPv4-mapped IPv6 forms (::ffff:169.254.x.x)
        if (raw.length == 16) {
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (raw[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped && (raw[10] & 0xFF) == 0xFF && (raw[11] & 0xFF) == 0xFF) {
                int b0 = raw[12] & 0xFF;
                int b1 = raw[13] & 0xFF;
                int b2 = raw[14] & 0xFF;
                int b3 = raw[15] & 0xFF;
                if (b0 == 169 && b1 == 254) {
                    if ((b2 == 169 && b3 == 254) || (b2 == 170 && b3 == 2)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
