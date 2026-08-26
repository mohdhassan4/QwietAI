package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class providing SSRF (Server-Side Request Forgery) protection by validating URLs against
 * private and reserved IP address ranges.
 */
public final class SsrfProtectionUtils {

    private SsrfProtectionUtils() {}

    /**
     * Validates that the given URL is safe from SSRF attacks.
     *
     * <p>Checks: 1. Scheme is http or https 2. Host resolves to a non-private, non-reserved IP
     * address
     *
     * @param urlString the URL to validate
     * @return true if the URL is safe to request, false otherwise
     */
    public static boolean isUrlSafeFromSsrf(String urlString) {
        if (urlString == null || urlString.isEmpty()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            return false;
        }

        String scheme = url.getProtocol();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Remove brackets for IPv6 literal addresses
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReservedAddress(address)) {
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            // Cannot resolve host - fail closed
            return false;
        }

        return true;
    }

    private static boolean isPrivateOrReservedAddress(InetAddress address) {
        byte[] addr = address.getAddress();

        if (addr.length == 4) {
            return isPrivateIPv4(addr);
        } else if (addr.length == 16) {
            return isPrivateIPv6(addr);
        }

        // Unknown address type - block
        return true;
    }

    private static boolean isPrivateIPv4(byte[] addr) {
        int b0 = addr[0] & 0xFF;
        int b1 = addr[1] & 0xFF;

        // 127.0.0.0/8 - Loopback
        if (b0 == 127) return true;
        // 10.0.0.0/8 - Private
        if (b0 == 10) return true;
        // 172.16.0.0/12 - Private
        if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;
        // 192.168.0.0/16 - Private
        if (b0 == 192 && b1 == 168) return true;
        // 169.254.0.0/16 - Link-local
        if (b0 == 169 && b1 == 254) return true;
        // 0.0.0.0/8 - Current network
        if (b0 == 0) return true;

        return false;
    }

    private static boolean isPrivateIPv6(byte[] addr) {
        // Check if IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        // Bytes 0-9 are 0, bytes 10-11 are 0xFF
        boolean isIPv4Mapped = true;
        for (int i = 0; i < 10; i++) {
            if (addr[i] != 0) {
                isIPv4Mapped = false;
                break;
            }
        }
        if (isIPv4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
            byte[] ipv4 = new byte[] {addr[12], addr[13], addr[14], addr[15]};
            return isPrivateIPv4(ipv4);
        }

        // Check if IPv4-compatible (::x.x.x.x)
        boolean isIPv4Compatible = true;
        for (int i = 0; i < 12; i++) {
            if (addr[i] != 0) {
                isIPv4Compatible = false;
                break;
            }
        }
        if (isIPv4Compatible) {
            byte[] ipv4 = new byte[] {addr[12], addr[13], addr[14], addr[15]};
            return isPrivateIPv4(ipv4);
        }

        // ::1 - Loopback
        boolean isLoopback = true;
        for (int i = 0; i < 15; i++) {
            if (addr[i] != 0) {
                isLoopback = false;
                break;
            }
        }
        if (isLoopback && addr[15] == 1) return true;

        // fe80::/10 - Link-local
        if ((addr[0] & 0xFF) == 0xFE && (addr[1] & 0xC0) == 0x80) return true;

        // fc00::/7 - Unique local address
        if ((addr[0] & 0xFE) == 0xFC) return true;

        return false;
    }
}
