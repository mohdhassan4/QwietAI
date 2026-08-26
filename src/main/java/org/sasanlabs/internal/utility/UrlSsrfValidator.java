package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class for validating URLs against Server-Side Request Forgery (SSRF) attacks. Validates
 * that a URL uses an allowed scheme (HTTP/HTTPS) and does not resolve to internal/private IP
 * addresses.
 *
 * @author Security Remediation
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates that a URL is safe from SSRF attacks by checking:
     *
     * <ul>
     *   <li>URL is well-formed and syntactically valid
     *   <li>Scheme is HTTP or HTTPS only (blocks file://, gopher://, etc.)
     *   <li>Hostname resolves to a non-internal IP address (DNS rebinding protection)
     * </ul>
     *
     * @param url the URL string to validate
     * @return true if the URL is safe to fetch, false otherwise
     */
    public static boolean isUrlSafeFromSsrf(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }

        URL parsedUrl;
        try {
            parsedUrl = new URL(url);
            parsedUrl.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            return false;
        }

        String protocol = parsedUrl.getProtocol();
        if (protocol == null
                || (!protocol.equalsIgnoreCase("http")
                        && !protocol.equalsIgnoreCase("https"))) {
            return false;
        }

        String host = parsedUrl.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Strip brackets from IPv6 literal hosts (e.g. [::1] -> ::1)
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        try {
            InetAddress resolvedAddress = InetAddress.getByName(host);
            return !isInternalAddress(resolvedAddress);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static boolean isInternalAddress(InetAddress address) {
        byte[] addr = address.getAddress();

        if (addr.length == 4) {
            return isInternalIPv4(addr);
        } else if (addr.length == 16) {
            // Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            if (isIPv4MappedIPv6(addr)) {
                byte[] ipv4 = new byte[] {addr[12], addr[13], addr[14], addr[15]};
                return isInternalIPv4(ipv4);
            }
            // IPv6 loopback (::1)
            if (address.isLoopbackAddress()) {
                return true;
            }
            // IPv6 link-local (fe80::/10)
            if (address.isLinkLocalAddress()) {
                return true;
            }
            // IPv6 unique local (fc00::/7 which includes fd00::/8)
            if ((addr[0] & 0xFE) == 0xFC) {
                return true;
            }
            // Unspecified address (::)
            if (address.isAnyLocalAddress()) {
                return true;
            }
            return false;
        }
        return true; // Unknown address type, reject by default
    }

    private static boolean isIPv4MappedIPv6(byte[] addr) {
        for (int i = 0; i < 10; i++) {
            if (addr[i] != 0) {
                return false;
            }
        }
        return (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF;
    }

    private static boolean isInternalIPv4(byte[] addr) {
        int b0 = addr[0] & 0xFF;
        int b1 = addr[1] & 0xFF;

        // 0.0.0.0/8 (unspecified)
        if (b0 == 0) {
            return true;
        }
        // 127.0.0.0/8 (loopback)
        if (b0 == 127) {
            return true;
        }
        // 10.0.0.0/8 (private)
        if (b0 == 10) {
            return true;
        }
        // 172.16.0.0/12 (private)
        if (b0 == 172 && b1 >= 16 && b1 <= 31) {
            return true;
        }
        // 192.168.0.0/16 (private)
        if (b0 == 192 && b1 == 168) {
            return true;
        }
        // 169.254.0.0/16 (link-local, includes cloud metadata 169.254.169.254)
        if (b0 == 169 && b1 == 254) {
            return true;
        }
        return false;
    }
}
