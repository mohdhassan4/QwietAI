package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class for URL validation to prevent SSRF attacks. Validates that a URL does not target
 * internal or private network addresses.
 */
public final class UrlValidationUtils {

    private UrlValidationUtils() {}

    /**
     * Checks whether the given URL targets an allowed (non-internal) host. Returns {@code false}
     * for URLs pointing to loopback, link-local, site-local, or other private/internal addresses.
     *
     * @param url the URL to validate
     * @return {@code true} if the host is allowed (public), {@code false} if it is
     *     internal/private or cannot be resolved
     */
    public static boolean isHostAllowed(URL url) {
        String protocol = url.getProtocol();
        if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
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

        // Reject "localhost" by name
        if ("localhost".equalsIgnoreCase(host)) {
            return false;
        }

        try {
            InetAddress address = InetAddress.getByName(host);
            if (address.isLoopbackAddress()
                    || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress()
                    || address.isAnyLocalAddress()
                    || address.isMulticastAddress()) {
                return false;
            }

            // Additional check for IPv4-mapped IPv6 addresses and other private ranges
            byte[] addrBytes = address.getAddress();
            if (isPrivateAddress(addrBytes)) {
                return false;
            }

            return true;
        } catch (UnknownHostException e) {
            // Cannot resolve host — reject
            return false;
        }
    }

    private static boolean isPrivateAddress(byte[] addr) {
        if (addr.length == 4) {
            // 10.0.0.0/8
            if ((addr[0] & 0xFF) == 10) {
                return true;
            }
            // 172.16.0.0/12
            if ((addr[0] & 0xFF) == 172 && (addr[1] & 0xFF) >= 16 && (addr[1] & 0xFF) <= 31) {
                return true;
            }
            // 192.168.0.0/16
            if ((addr[0] & 0xFF) == 192 && (addr[1] & 0xFF) == 168) {
                return true;
            }
            // 127.0.0.0/8 (loopback)
            if ((addr[0] & 0xFF) == 127) {
                return true;
            }
            // 169.254.0.0/16 (link-local)
            if ((addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254) {
                return true;
            }
            // 0.0.0.0
            if (addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0) {
                return true;
            }
        } else if (addr.length == 16) {
            // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
            boolean isIPv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isIPv4Mapped = false;
                    break;
                }
            }
            if (isIPv4Mapped
                    && (addr[10] & 0xFF) == 0xFF
                    && (addr[11] & 0xFF) == 0xFF) {
                byte[] ipv4 = new byte[4];
                System.arraycopy(addr, 12, ipv4, 0, 4);
                return isPrivateAddress(ipv4);
            }
            // ::1 (IPv6 loopback)
            boolean isLoopback = true;
            for (int i = 0; i < 15; i++) {
                if (addr[i] != 0) {
                    isLoopback = false;
                    break;
                }
            }
            if (isLoopback && addr[15] == 1) {
                return true;
            }
        }
        return false;
    }
}
