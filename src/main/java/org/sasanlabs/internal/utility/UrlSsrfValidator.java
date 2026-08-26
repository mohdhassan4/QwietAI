package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Validates
 * scheme, resolves hostname and checks resolved IP addresses against private/internal ranges.
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates that the given URL is safe from SSRF attacks.
     *
     * <p>Checks performed:
     *
     * <ul>
     *   <li>URL is syntactically valid
     *   <li>Scheme is http or https only
     *   <li>Hostname is not a localhost alias
     *   <li>Resolved IP addresses are not in private/internal ranges
     * </ul>
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe, false otherwise
     */
    public static boolean isUrlSafeFromSsrf(String urlString) {
        return validateAndGetSafeUrl(urlString) != null;
    }

    /**
     * Validates the URL and returns a URL object with the host replaced by the resolved IP address
     * to prevent DNS rebinding attacks. Returns null if the URL is not safe.
     *
     * @param urlString the URL string to validate
     * @return a safe URL using the resolved IP, or null if validation fails
     */
    public static URL validateAndGetSafeUrl(String urlString) {
        URL url;
        try {
            url = new URL(urlString);
            url.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            return null;
        }

        String scheme = url.getProtocol();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            return null;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return null;
        }

        if (isLocalhostName(host)) {
            return null;
        }

        InetAddress safeAddress;
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            safeAddress = null;
            for (InetAddress address : addresses) {
                if (isPrivateOrInternalAddress(address)) {
                    return null;
                }
                if (safeAddress == null) {
                    safeAddress = address;
                }
            }
        } catch (UnknownHostException e) {
            return null;
        }

        if (safeAddress == null) {
            return null;
        }

        // Build a URL using the resolved IP to prevent DNS rebinding
        try {
            String resolvedHost = safeAddress.getHostAddress();
            int port = url.getPort();
            String path = url.getPath();
            String query = url.getQuery();
            String portStr = (port == -1) ? "" : ":" + port;
            String queryStr = (query == null) ? "" : "?" + query;
            return new URL(scheme + "://" + resolvedHost + portStr + path + queryStr);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    private static boolean isLocalhostName(String host) {
        String lower = host.toLowerCase();
        // Strip brackets for IPv6 literal checks
        if (lower.startsWith("[") && lower.endsWith("]")) {
            lower = lower.substring(1, lower.length() - 1);
        }
        return lower.equals("localhost")
                || lower.equals("localhost.localdomain")
                || lower.equals("ip6-localhost")
                || lower.equals("ip6-loopback")
                || lower.equals("[::1]")
                || lower.equals("::1")
                || lower.equals("0.0.0.0")
                || lower.endsWith(".localhost");
    }

    private static boolean isPrivateOrInternalAddress(InetAddress address) {
        byte[] addr = address.getAddress();

        if (address.isLoopbackAddress()) {
            return true;
        }
        if (address.isLinkLocalAddress()) {
            return true;
        }
        if (address.isSiteLocalAddress()) {
            return true;
        }
        if (address.isAnyLocalAddress()) {
            return true;
        }

        // IPv4 checks
        if (addr.length == 4) {
            int first = addr[0] & 0xFF;
            int second = addr[1] & 0xFF;

            // 127.0.0.0/8 - loopback
            if (first == 127) {
                return true;
            }
            // 10.0.0.0/8 - private
            if (first == 10) {
                return true;
            }
            // 172.16.0.0/12 - private
            if (first == 172 && second >= 16 && second <= 31) {
                return true;
            }
            // 192.168.0.0/16 - private
            if (first == 192 && second == 168) {
                return true;
            }
            // 169.254.0.0/16 - link-local (includes metadata endpoint 169.254.169.254)
            if (first == 169 && second == 254) {
                return true;
            }
            // 0.0.0.0/8
            if (first == 0) {
                return true;
            }
        }

        // IPv6 checks
        if (addr.length == 16) {
            // ::1 loopback
            if (address.isLoopbackAddress()) {
                return true;
            }
            // fc00::/7 - unique local addresses
            int first = addr[0] & 0xFF;
            if ((first & 0xFE) == 0xFC) {
                return true;
            }
            // fe80::/10 - link-local
            if (first == 0xFE && (addr[1] & 0xC0) == 0x80) {
                return true;
            }
            // IPv4-mapped IPv6 (::ffff:x.x.x.x) - check the embedded IPv4
            if (isIpv4MappedIpv6(addr)) {
                byte[] ipv4 = new byte[4];
                System.arraycopy(addr, 12, ipv4, 0, 4);
                try {
                    InetAddress ipv4Address = InetAddress.getByAddress(ipv4);
                    return isPrivateOrInternalAddress(ipv4Address);
                } catch (UnknownHostException e) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean isIpv4MappedIpv6(byte[] addr) {
        if (addr.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (addr[i] != 0) {
                return false;
            }
        }
        return (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF;
    }
}
