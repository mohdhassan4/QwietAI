package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class for validating URLs before making server-side HTTP requests to prevent SSRF
 * (Server-Side Request Forgery) attacks.
 *
 * <p>Validates that:
 *
 * <ul>
 *   <li>The URL has a valid syntax
 *   <li>The scheme is http or https only
 *   <li>The resolved IP address is not a private, loopback, link-local, or internal address
 * </ul>
 */
public final class UrlSafetyValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSafetyValidator.class);

    private UrlSafetyValidator() {}

    /**
     * Validates that the given URL is safe for making server-side HTTP requests.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe for server-side requests, false otherwise
     */
    public static boolean isUrlSafeForServerSideRequest(String urlString) {
        if (urlString == null || urlString.isEmpty()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
            url.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.debug("URL validation failed - malformed URL: {}", LogSanitizer.sanitize(urlString), e);
            return false;
        }

        // Only allow http and https schemes
        String scheme = url.getProtocol();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            LOGGER.debug("URL validation failed - disallowed scheme: {}", LogSanitizer.sanitize(scheme));
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            LOGGER.debug("URL validation failed - empty host");
            return false;
        }

        // Remove brackets from IPv6 addresses
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        // Resolve the hostname to IP address(es) and validate
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (!isAddressSafe(address)) {
                    LOGGER.debug(
                            "URL validation failed - resolved to unsafe address: {}",
                            address.getHostAddress());
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            // Fail closed - if we cannot resolve the host, reject the request
            LOGGER.debug("URL validation failed - cannot resolve host: {}", LogSanitizer.sanitize(host), e);
            return false;
        }

        return true;
    }

    /**
     * Checks whether a resolved IP address is safe (not internal/private/loopback/link-local).
     *
     * <p>Rejects:
     *
     * <ul>
     *   <li>Loopback addresses (127.0.0.0/8, ::1)
     *   <li>Private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fd00::/8)
     *   <li>Link-local addresses (169.254.0.0/16, fe80::/10)
     *   <li>Any site-local or multicast address
     * </ul>
     *
     * @param address the InetAddress to check
     * @return true if the address is safe (public), false if it is internal/private
     */
    static boolean isAddressSafe(InetAddress address) {
        if (address.isLoopbackAddress()) {
            return false;
        }
        if (address.isSiteLocalAddress()) {
            return false;
        }
        if (address.isLinkLocalAddress()) {
            return false;
        }
        if (address.isAnyLocalAddress()) {
            return false;
        }
        if (address.isMulticastAddress()) {
            return false;
        }

        // Additional check for IPv4-mapped IPv6 addresses (e.g., ::ffff:169.254.169.254)
        byte[] addrBytes = address.getAddress();
        if (addrBytes.length == 16) {
            // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addrBytes[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped && addrBytes[10] == (byte) 0xff && addrBytes[11] == (byte) 0xff) {
                // Extract the IPv4 part and check it
                int octet1 = addrBytes[12] & 0xFF;
                int octet2 = addrBytes[13] & 0xFF;
                if (isPrivateIpv4(octet1, octet2)) {
                    return false;
                }
            }

            // Check for fd00::/8 (unique local)
            if ((addrBytes[0] & 0xFF) == 0xfd) {
                return false;
            }
        }

        // Additional explicit check for IPv4 private ranges
        if (addrBytes.length == 4) {
            int octet1 = addrBytes[0] & 0xFF;
            int octet2 = addrBytes[1] & 0xFF;
            if (isPrivateIpv4(octet1, octet2)) {
                return false;
            }
        }

        return true;
    }

    private static boolean isPrivateIpv4(int octet1, int octet2) {
        // 127.0.0.0/8 - loopback
        if (octet1 == 127) {
            return true;
        }
        // 10.0.0.0/8 - private
        if (octet1 == 10) {
            return true;
        }
        // 172.16.0.0/12 - private
        if (octet1 == 172 && octet2 >= 16 && octet2 <= 31) {
            return true;
        }
        // 192.168.0.0/16 - private
        if (octet1 == 192 && octet2 == 168) {
            return true;
        }
        // 169.254.0.0/16 - link-local / metadata
        if (octet1 == 169 && octet2 == 254) {
            return true;
        }
        return false;
    }
}
