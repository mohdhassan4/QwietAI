package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class for SSRF (Server-Side Request Forgery) URL validation. Validates that a URL does
 * not target internal/private network addresses.
 */
public final class SsrfValidator {

    private SsrfValidator() {}

    /**
     * Returns true if the given URL targets an internal or private address that should not be
     * accessed from a server-side request.
     *
     * @param url the URL to validate
     * @return true if the URL host resolves to an internal address or uses the file protocol
     */
    public static boolean isInternalUrl(URL url) {
        String protocol = url.getProtocol();
        if ("file".equalsIgnoreCase(protocol)) {
            return true;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return true;
        }

        // Strip brackets for IPv6 literal addresses
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        try {
            InetAddress address = InetAddress.getByName(host);
            return isAddressInternal(address);
        } catch (UnknownHostException e) {
            // If we cannot resolve the host, fail closed (block the request)
            return true;
        }
    }

    /**
     * Returns true if the given InetAddress is a loopback, link-local, site-local, or otherwise
     * private/internal address.
     */
    private static boolean isAddressInternal(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()) {
            return true;
        }

        byte[] addr = address.getAddress();

        if (addr.length == 4) {
            return isIpv4Internal(addr);
        } else if (addr.length == 16) {
            return isIpv6Internal(addr);
        }

        return false;
    }

    private static boolean isIpv4Internal(byte[] addr) {
        int b0 = addr[0] & 0xFF;
        int b1 = addr[1] & 0xFF;

        if (b0 == 10) return true; // 10.0.0.0/8
        if (b0 == 172 && b1 >= 16 && b1 <= 31) return true; // 172.16.0.0/12
        if (b0 == 192 && b1 == 168) return true; // 192.168.0.0/16
        if (b0 == 127) return true; // 127.0.0.0/8
        if (b0 == 169 && b1 == 254) return true; // 169.254.0.0/16 (link-local)
        if (b0 == 0) return true; // 0.0.0.0/8

        return false;
    }

    private static boolean isIpv6Internal(byte[] addr) {
        // Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
        boolean isMapped = true;
        for (int i = 0; i < 10; i++) {
            if (addr[i] != 0) {
                isMapped = false;
                break;
            }
        }
        if (isMapped && addr[10] == (byte) 0xff && addr[11] == (byte) 0xff) {
            byte[] v4Bytes = new byte[4];
            System.arraycopy(addr, 12, v4Bytes, 0, 4);
            return isIpv4Internal(v4Bytes);
        }

        // Unique local address (fc00::/7)
        if ((addr[0] & 0xFE) == 0xFC) return true;

        return false;
    }
}
