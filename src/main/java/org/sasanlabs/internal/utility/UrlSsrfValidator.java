package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Ensures that
 * only http/https schemes are allowed and that the resolved host IP is not in a private or internal
 * network range.
 */
public final class UrlSsrfValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSsrfValidator.class);

    private UrlSsrfValidator() {}

    /**
     * Validates that the given URL is safe from SSRF attacks.
     *
     * @param urlString the URL string to validate
     * @return true if the URL uses an allowed scheme and resolves to a public IP address
     */
    public static boolean isSafeFromSsrf(String urlString) {
        if (urlString == null || urlString.isEmpty()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            LOGGER.error("URL is malformed: {}", urlString, e);
            return false;
        }

        // Only allow http and https schemes
        String protocol = url.getProtocol();
        if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
            LOGGER.warn("Blocked URL with disallowed scheme: {}", protocol);
            return false;
        }

        // Resolve the hostname and check the IP address
        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Strip brackets from IPv6 literal addresses
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrInternalAddress(address)) {
                    LOGGER.warn(
                            "Blocked URL resolving to private/internal IP: {} -> {}",
                            host,
                            address.getHostAddress());
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            LOGGER.error("Cannot resolve host: {}", host, e);
            return false;
        }

        return true;
    }

    /**
     * Checks if the given InetAddress is a private, loopback, link-local, or otherwise internal
     * address that should not be accessed via SSRF.
     */
    private static boolean isPrivateOrInternalAddress(InetAddress address) {
        // Loopback: 127.0.0.0/8, ::1
        if (address.isLoopbackAddress()) {
            return true;
        }

        // Link-local: 169.254.0.0/16, fe80::/10
        if (address.isLinkLocalAddress()) {
            return true;
        }

        // Site-local: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fec0::/10
        if (address.isSiteLocalAddress()) {
            return true;
        }

        // Any local address (0.0.0.0, ::0)
        if (address.isAnyLocalAddress()) {
            return true;
        }

        // Multicast addresses
        if (address.isMulticastAddress()) {
            return true;
        }

        byte[] addrBytes = address.getAddress();

        if (addrBytes.length == 4) {
            // IPv4-specific checks
            // 100.64.0.0/10 (Shared Address Space / CGNAT)
            if ((addrBytes[0] & 0xFF) == 100
                    && (addrBytes[1] & 0xFF) >= 64
                    && (addrBytes[1] & 0xFF) <= 127) {
                return true;
            }
            // 192.0.0.0/24 (IETF Protocol Assignments)
            if ((addrBytes[0] & 0xFF) == 192
                    && (addrBytes[1] & 0xFF) == 0
                    && (addrBytes[2] & 0xFF) == 0) {
                return true;
            }
        } else if (addrBytes.length == 16) {
            // IPv6 Unique Local Address fc00::/7
            if ((addrBytes[0] & 0xFE) == 0xFC) {
                return true;
            }
            // IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) - check the embedded IPv4
            if (isIpv4MappedIpv6(addrBytes)) {
                int b0 = addrBytes[12] & 0xFF;
                int b1 = addrBytes[13] & 0xFF;
                int b2 = addrBytes[14] & 0xFF;
                // 10.0.0.0/8
                if (b0 == 10) {
                    return true;
                }
                // 127.0.0.0/8
                if (b0 == 127) {
                    return true;
                }
                // 172.16.0.0/12
                if (b0 == 172 && b1 >= 16 && b1 <= 31) {
                    return true;
                }
                // 192.168.0.0/16
                if (b0 == 192 && b1 == 168) {
                    return true;
                }
                // 169.254.0.0/16
                if (b0 == 169 && b1 == 254) {
                    return true;
                }
                // 0.0.0.0
                if (b0 == 0 && b1 == 0 && b2 == 0 && (addrBytes[15] & 0xFF) == 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /** Checks whether the address bytes represent an IPv4-mapped IPv6 address (::ffff:x.x.x.x). */
    private static boolean isIpv4MappedIpv6(byte[] addrBytes) {
        if (addrBytes.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (addrBytes[i] != 0) {
                return false;
            }
        }
        return (addrBytes[10] & 0xFF) == 0xFF && (addrBytes[11] & 0xFF) == 0xFF;
    }
}
