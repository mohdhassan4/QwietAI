package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class providing SSRF (Server-Side Request Forgery) validation. Resolves the hostname of a
 * URL and rejects requests targeting private, internal, link-local, or cloud metadata IP addresses.
 *
 * @author SasanLabs
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates that the given URL does not resolve to a private, internal, link-local, or loopback
     * IP address. Only http and https protocols are allowed.
     *
     * @param url the URL to validate
     * @return true if the URL is safe (public IP, allowed protocol), false otherwise
     */
    public static boolean isSafeUrl(URL url) {
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

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReserved(address)) {
                    return false;
                }
            }
            return true;
        } catch (UnknownHostException e) {
            // Cannot resolve host — block the request
            return false;
        }
    }

    /**
     * Checks whether the given InetAddress belongs to a private, loopback, link-local, or
     * otherwise reserved range that should not be accessed via SSRF.
     */
    private static boolean isPrivateOrReserved(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCloudMetadataAddress(address);
    }

    /**
     * Specifically checks for cloud metadata service addresses (169.254.169.254, 169.254.170.2)
     * which are link-local but warrant an explicit check for clarity.
     */
    private static boolean isCloudMetadataAddress(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            // 169.254.0.0/16
            return (addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254;
        }
        if (addr.length == 16) {
            // Check for IPv4-mapped IPv6 ::ffff:169.254.x.x
            boolean isV4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isV4Mapped = false;
                    break;
                }
            }
            if (isV4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                return (addr[12] & 0xFF) == 169 && (addr[13] & 0xFF) == 254;
            }
        }
        return false;
    }
}
