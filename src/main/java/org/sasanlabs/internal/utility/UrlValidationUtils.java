package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class for URL validation to prevent Server-Side Request Forgery (SSRF) attacks.
 *
 * <p>Validates that a URL targets only public, external hosts using allowed schemes (http/https).
 */
public final class UrlValidationUtils {

    private UrlValidationUtils() {}

    /**
     * Validates that the given URL is safe from SSRF attacks.
     *
     * @param url the URL to validate
     * @return true if the URL is safe to fetch (public host, allowed scheme), false otherwise
     */
    public static boolean isUrlSafeFromSsrf(URL url) {
        String protocol = url.getProtocol();
        if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Strip brackets from IPv6 literal hosts
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
        } catch (UnknownHostException e) {
            // Cannot resolve host — reject to be safe
            return false;
        }

        return true;
    }

    /**
     * Validates that the given URL string is safe from SSRF attacks.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe to fetch, false otherwise
     */
    public static boolean isUrlSafeFromSsrf(String urlString) {
        try {
            URL url = new URL(urlString);
            return isUrlSafeFromSsrf(url);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isPrivateOrReserved(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCloudMetadata(address)
                || isCarrierGradeNat(address);
    }

    /**
     * Checks for cloud metadata endpoint IPs (169.254.169.254, 169.254.170.2).
     */
    private static boolean isCloudMetadata(InetAddress address) {
        // Link-local is already caught by isLinkLocalAddress() for 169.254.x.x,
        // but we explicitly check known metadata IPs for clarity.
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            int b0 = addr[0] & 0xFF;
            int b1 = addr[1] & 0xFF;
            // 169.254.0.0/16 (link-local, includes metadata endpoints)
            if (b0 == 169 && b1 == 254) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks for Carrier-Grade NAT range 100.64.0.0/10.
     */
    private static boolean isCarrierGradeNat(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            int b0 = addr[0] & 0xFF;
            int b1 = addr[1] & 0xFF;
            // 100.64.0.0/10 => first byte 100, second byte 64-127
            if (b0 == 100 && b1 >= 64 && b1 <= 127) {
                return true;
            }
        }
        return false;
    }
}
