package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class to validate URLs against SSRF attacks. Ensures that URLs use only http/https
 * schemes and do not resolve to private/internal/link-local IP addresses.
 */
public final class UrlSsrfValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSsrfValidator.class);

    private UrlSsrfValidator() {}

    /**
     * Validates a URL string is safe from SSRF attacks. Throws SecurityException if the URL is
     * unsafe, ensuring taint analysis recognizes the validation at the sink.
     *
     * @param urlString the URL to validate
     * @throws SecurityException if the URL is not safe for server-side requests
     */
    public static void validateUrl(String urlString) {
        if (!isSafeUrl(urlString)) {
            throw new SecurityException(
                    "URL failed SSRF validation: request to internal/disallowed destination blocked");
        }
    }

    /**
     * Validates a URL string is safe from SSRF attacks.
     *
     * @param urlString the URL to validate
     * @return true if the URL is safe (public, http/https only), false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            url.toURI();

            String protocol = url.getProtocol().toLowerCase();
            if (!"http".equals(protocol) && !"https".equals(protocol)) {
                LOGGER.debug("Rejected URL with disallowed scheme: {}", protocol);
                return false;
            }

            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                LOGGER.debug("Rejected URL with empty host");
                return false;
            }

            // Strip IPv6 brackets for resolution
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }

            InetAddress[] addresses;
            try {
                addresses = InetAddress.getAllByName(host);
            } catch (UnknownHostException e) {
                LOGGER.debug("Rejected URL with unresolvable host: {}", host);
                return false;
            }

            for (InetAddress address : addresses) {
                if (isPrivateOrReserved(address)) {
                    LOGGER.debug(
                            "Rejected URL resolving to private/reserved address: {}", address);
                    return false;
                }
            }

            return true;
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.debug("Rejected malformed URL: {}", urlString, e);
            return false;
        }
    }

    /**
     * Checks if an InetAddress is private, loopback, link-local, or otherwise reserved/internal.
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
        if (address.isMulticastAddress()) {
            return true;
        }

        byte[] addr = address.getAddress();

        // IPv4-mapped IPv6 addresses: check the embedded IPv4
        if (addr.length == 16) {
            boolean isIPv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isIPv4Mapped = false;
                    break;
                }
            }
            if (isIPv4Mapped && addr[10] == (byte) 0xff && addr[11] == (byte) 0xff) {
                byte[] ipv4 = new byte[4];
                System.arraycopy(addr, 12, ipv4, 0, 4);
                try {
                    InetAddress ipv4Addr = InetAddress.getByAddress(ipv4);
                    return isPrivateOrReserved(ipv4Addr);
                } catch (UnknownHostException e) {
                    return true;
                }
            }
        }

        // Additional check for 169.254.0.0/16 (link-local, covers metadata endpoints)
        if (addr.length == 4) {
            int firstOctet = addr[0] & 0xFF;
            int secondOctet = addr[1] & 0xFF;
            if (firstOctet == 169 && secondOctet == 254) {
                return true;
            }
            // 100.64.0.0/10 (Shared Address Space / CGN)
            if (firstOctet == 100 && (secondOctet & 0xC0) == 64) {
                return true;
            }
        }

        return false;
    }
}
