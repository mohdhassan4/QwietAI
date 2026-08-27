package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Validates
 * that:
 *
 * <ul>
 *   <li>Only http/https schemes are allowed
 *   <li>The resolved IP address is not in private/internal ranges
 *   <li>The target is not localhost or link-local
 * </ul>
 */
public final class UrlSsrfValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSsrfValidator.class);

    private UrlSsrfValidator() {}

    /**
     * Validates that the given URL string is syntactically valid, uses an allowed scheme
     * (http/https), and does not resolve to a private or internal IP address.
     *
     * @param urlString the URL to validate
     * @return true if the URL is safe to fetch; false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
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

        String scheme = url.getProtocol();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            LOGGER.warn("Blocked URL with disallowed scheme: {}", scheme);
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            LOGGER.warn("Blocked URL with empty host");
            return false;
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReserved(address)) {
                    LOGGER.warn(
                            "Blocked URL {} resolving to private/internal address: {}",
                            urlString,
                            address.getHostAddress());
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            LOGGER.error("Cannot resolve host for URL: {}", urlString, e);
            return false;
        }

        return true;
    }

    /**
     * Checks if the given InetAddress is a private, loopback, link-local, or otherwise reserved
     * address that should not be reachable via SSRF.
     */
    private static boolean isPrivateOrReserved(InetAddress address) {
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

        byte[] addrBytes = address.getAddress();

        if (addrBytes.length == 4) {
            // 169.254.0.0/16 (link-local, includes metadata endpoint 169.254.169.254)
            if ((addrBytes[0] & 0xFF) == 169 && (addrBytes[1] & 0xFF) == 254) {
                return true;
            }
            // 100.64.0.0/10 (Shared Address Space / CGN)
            if ((addrBytes[0] & 0xFF) == 100
                    && (addrBytes[1] & 0xFF) >= 64
                    && (addrBytes[1] & 0xFF) <= 127) {
                return true;
            }
        }

        if (addrBytes.length == 16) {
            // fd00::/8 (unique local addresses)
            if ((addrBytes[0] & 0xFF) == 0xFD) {
                return true;
            }
            // fc00::/7 (unique local addresses)
            if ((addrBytes[0] & 0xFE) == 0xFC) {
                return true;
            }
            // fe80::/10 (link-local, already covered by isLinkLocalAddress but explicit)
            if ((addrBytes[0] & 0xFF) == 0xFE && (addrBytes[1] & 0xC0) == 0x80) {
                return true;
            }
            // ::ffff:x.x.x.x (IPv4-mapped IPv6) - check the embedded IPv4
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addrBytes[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped
                    && (addrBytes[10] & 0xFF) == 0xFF
                    && (addrBytes[11] & 0xFF) == 0xFF) {
                // Extract the embedded IPv4 and check it
                int b0 = addrBytes[12] & 0xFF;
                int b1 = addrBytes[13] & 0xFF;
                if (b0 == 127) {
                    return true;
                }
                if (b0 == 10) {
                    return true;
                }
                if (b0 == 172 && b1 >= 16 && b1 <= 31) {
                    return true;
                }
                if (b0 == 192 && b1 == 168) {
                    return true;
                }
                if (b0 == 169 && b1 == 254) {
                    return true;
                }
                if (b0 == 0) {
                    return true;
                }
            }
        }

        return false;
    }
}
