package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Ensures that
 * user-supplied URLs do not target internal, private, loopback, or link-local addresses.
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates that a URL string is safe from SSRF by checking:
     *
     * <ul>
     *   <li>Only http or https schemes are allowed
     *   <li>The resolved IP address is not loopback, link-local, private, or site-local
     * </ul>
     *
     * @param urlString the user-supplied URL string
     * @return true if the URL is considered safe for server-side requests, false otherwise
     */
    public static boolean isUrlSafeForServerSideRequest(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }

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
        if (host == null || host.isBlank()) {
            return false;
        }

        // Strip IPv6 brackets if present
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
            // Cannot resolve host — reject to be safe
            return false;
        }

        return true;
    }

    private static boolean isPrivateOrReservedAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCarrierGradeNat(address)
                || isMetadataAddress(address);
    }

    /**
     * Checks for Carrier-Grade NAT range 100.64.0.0/10 which can also be internal.
     */
    private static boolean isCarrierGradeNat(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            int firstOctet = addr[0] & 0xFF;
            int secondOctet = addr[1] & 0xFF;
            // 100.64.0.0/10 => first octet 100, second octet 64-127
            return firstOctet == 100 && secondOctet >= 64 && secondOctet <= 127;
        }
        return false;
    }

    /**
     * Checks for cloud metadata addresses (169.254.169.254, 169.254.170.2) that are commonly used
     * for instance metadata services.
     */
    private static boolean isMetadataAddress(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            int firstOctet = addr[0] & 0xFF;
            int secondOctet = addr[1] & 0xFF;
            // 169.254.0.0/16 is link-local, already caught by isLinkLocalAddress()
            // but explicitly check common metadata endpoints
            if (firstOctet == 169 && secondOctet == 254) {
                return true;
            }
        }
        // Also check IPv4-mapped IPv6 addresses for metadata range
        if (addr.length == 16) {
            // Check if it is an IPv4-mapped IPv6 (::ffff:x.x.x.x)
            boolean isV4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isV4Mapped = false;
                    break;
                }
            }
            if (isV4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                int firstOctet = addr[12] & 0xFF;
                int secondOctet = addr[13] & 0xFF;
                if (firstOctet == 169 && secondOctet == 254) {
                    return true;
                }
            }
        }
        return false;
    }
}
