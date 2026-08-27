package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Blocks
 * requests to private/internal IP ranges, link-local addresses, loopback, and non-HTTP(S) schemes.
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates that a URL is safe from SSRF attacks.
     *
     * @param url the URL to validate
     * @return true if the URL targets a public, non-internal address over HTTP(S)
     */
    public static boolean isSafeFromSsrf(URL url) {
        String protocol = url.getProtocol();
        if (protocol == null || (!protocol.equalsIgnoreCase("http")
                && !protocol.equalsIgnoreCase("https"))) {
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Strip brackets from IPv6 literals
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        try {
            InetAddress address = InetAddress.getByName(host);
            return !isBlockedAddress(address);
        } catch (UnknownHostException e) {
            // Cannot resolve host — block to be safe
            return false;
        }
    }

    private static boolean isBlockedAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCloudMetadataAddress(address);
    }

    private static boolean isCloudMetadataAddress(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            // 169.254.0.0/16 (link-local, includes cloud metadata 169.254.169.254)
            return (addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254;
        }
        if (addr.length == 16) {
            // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x) pointing to blocked ranges
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                // Extract the IPv4 portion and check
                byte[] ipv4 = new byte[] {addr[12], addr[13], addr[14], addr[15]};
                try {
                    InetAddress ipv4Addr = InetAddress.getByAddress(ipv4);
                    return isBlockedAddress(ipv4Addr);
                } catch (UnknownHostException e) {
                    return true;
                }
            }
            // fd00::/8 (unique local)
            return (addr[0] & 0xFF) == 0xFD;
        }
        return false;
    }
}
