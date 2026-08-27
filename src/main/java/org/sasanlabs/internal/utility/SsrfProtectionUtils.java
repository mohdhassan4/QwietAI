package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class providing SSRF protection by validating URLs against internal/private IP ranges,
 * cloud metadata endpoints, and dangerous protocols.
 *
 * @author Security Remediation
 */
public final class SsrfProtectionUtils {

    private static final transient Logger LOGGER = LogManager.getLogger(SsrfProtectionUtils.class);

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    private SsrfProtectionUtils() {}

    /**
     * Validates that a URL is safe to request from the server side. Rejects URLs that target
     * internal/private IP ranges, cloud metadata endpoints, link-local addresses, and non-HTTP
     * schemes.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe to fetch; false otherwise
     */
    public static boolean isUrlSafe(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
            url.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.error(
                    "Provided URL: {} is not valid and following exception occurred",
                    urlString,
                    e);
            return false;
        }

        // Only allow http and https schemes
        String scheme = url.getProtocol().toLowerCase();
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            LOGGER.warn("SSRF protection: blocked non-HTTP scheme: {}", scheme);
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isBlank()) {
            return false;
        }

        // Resolve the hostname to IP address(es) and validate each
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReservedAddress(address)) {
                    LOGGER.warn(
                            "SSRF protection: blocked request to internal/private address: {}",
                            address.getHostAddress());
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            LOGGER.error("SSRF protection: unable to resolve host: {}", host, e);
            return false;
        }

        return true;
    }

    /**
     * Checks if the given InetAddress is a private, loopback, link-local, multicast, or otherwise
     * reserved address that should not be accessed via SSRF.
     */
    private static boolean isPrivateOrReservedAddress(InetAddress address) {
        // Loopback (127.0.0.0/8, ::1)
        if (address.isLoopbackAddress()) {
            return true;
        }

        // Link-local (169.254.0.0/16, fe80::/10) - includes cloud metadata 169.254.169.254
        if (address.isLinkLocalAddress()) {
            return true;
        }

        // Site-local / private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fec0::/10)
        if (address.isSiteLocalAddress()) {
            return true;
        }

        // Multicast
        if (address.isMulticastAddress()) {
            return true;
        }

        // Any local address (0.0.0.0, ::)
        if (address.isAnyLocalAddress()) {
            return true;
        }

        // Additional check for IPv4-mapped IPv6 addresses that may bypass the above checks
        byte[] addrBytes = address.getAddress();
        if (addrBytes.length == 4) {
            // IPv4 specific checks
            int firstOctet = addrBytes[0] & 0xFF;
            int secondOctet = addrBytes[1] & 0xFF;

            // 169.254.0.0/16 (link-local, includes cloud metadata endpoint)
            if (firstOctet == 169 && secondOctet == 254) {
                return true;
            }

            // 10.0.0.0/8
            if (firstOctet == 10) {
                return true;
            }

            // 172.16.0.0/12
            if (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31) {
                return true;
            }

            // 192.168.0.0/16
            if (firstOctet == 192 && secondOctet == 168) {
                return true;
            }

            // 127.0.0.0/8
            if (firstOctet == 127) {
                return true;
            }

            // 0.0.0.0/8
            if (firstOctet == 0) {
                return true;
            }
        } else if (addrBytes.length == 16) {
            // IPv6 specific checks for mapped/compatible IPv4 addresses
            // Check for ::ffff:x.x.x.x (IPv4-mapped IPv6)
            boolean isIPv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addrBytes[i] != 0) {
                    isIPv4Mapped = false;
                    break;
                }
            }
            if (isIPv4Mapped
                    && (addrBytes[10] & 0xFF) == 0xFF
                    && (addrBytes[11] & 0xFF) == 0xFF) {
                int firstOctet = addrBytes[12] & 0xFF;
                int secondOctet = addrBytes[13] & 0xFF;

                if (firstOctet == 169 && secondOctet == 254) {
                    return true;
                }
                if (firstOctet == 10) {
                    return true;
                }
                if (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31) {
                    return true;
                }
                if (firstOctet == 192 && secondOctet == 168) {
                    return true;
                }
                if (firstOctet == 127) {
                    return true;
                }
                if (firstOctet == 0) {
                    return true;
                }
            }
        }

        return false;
    }
}
