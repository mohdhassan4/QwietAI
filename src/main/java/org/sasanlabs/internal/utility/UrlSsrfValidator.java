package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class to validate URLs against SSRF attacks. Blocks requests to private/internal IP
 * ranges and restricts allowed schemes to http and https.
 */
public final class UrlSsrfValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSsrfValidator.class);

    private UrlSsrfValidator() {}

    /**
     * Sanitizes a string for safe inclusion in log messages by replacing control characters
     * (newlines, carriage returns, tabs) that could be used for log forging.
     *
     * @param input the string to sanitize
     * @return sanitized string safe for logging
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll("[\\r\\n\\t\\u0000-\\u001F\\u007F]", "_");
    }

    /**
     * Validates whether the given URL is safe from SSRF attacks.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe (public, non-internal), false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            url.toURI();

            String scheme = url.getProtocol().toLowerCase();
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                LOGGER.warn("Blocked URL with disallowed scheme: {}", sanitizeForLog(scheme));
                return false;
            }

            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                LOGGER.warn("Blocked URL with empty host");
                return false;
            }

            // Strip IPv6 brackets for address resolution
            String cleanHost = host;
            if (cleanHost.startsWith("[") && cleanHost.endsWith("]")) {
                cleanHost = cleanHost.substring(1, cleanHost.length() - 1);
            }

            InetAddress[] addresses;
            try {
                addresses = InetAddress.getAllByName(cleanHost);
            } catch (UnknownHostException e) {
                LOGGER.warn("Could not resolve host: {}", sanitizeForLog(host));
                return false;
            }

            for (InetAddress addr : addresses) {
                if (isPrivateOrReserved(addr)) {
                    LOGGER.warn(
                            "Blocked URL targeting private/internal address: {} -> {}",
                            sanitizeForLog(host),
                            addr.getHostAddress());
                    return false;
                }
            }

            return true;
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.error("Invalid URL: {}", sanitizeForLog(urlString), e);
            return false;
        }
    }

    /**
     * Checks whether an InetAddress belongs to a private, loopback, link-local, or otherwise
     * reserved network range that should not be accessible via SSRF.
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
     * Checks for cloud metadata service addresses (169.254.169.254, 169.254.170.2 and their IPv6
     * mapped equivalents).
     */
    private static boolean isCloudMetadataAddress(InetAddress address) {
        byte[] bytes = address.getAddress();

        // IPv4 check (4 bytes)
        if (bytes.length == 4) {
            // 169.254.169.254 (AWS/GCP/Azure metadata)
            if (bytes[0] == (byte) 169
                    && bytes[1] == (byte) 254
                    && bytes[2] == (byte) 169
                    && bytes[3] == (byte) 254) {
                return true;
            }
            // 169.254.170.2 (AWS ECS task metadata)
            if (bytes[0] == (byte) 169
                    && bytes[1] == (byte) 254
                    && bytes[2] == (byte) 170
                    && bytes[3] == (byte) 2) {
                return true;
            }
        }

        // IPv6 mapped IPv4 check (16 bytes, ::ffff:A.B.C.D)
        if (bytes.length == 16) {
            boolean isV4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    isV4Mapped = false;
                    break;
                }
            }
            if (isV4Mapped && bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff) {
                // Check the IPv4 part (last 4 bytes)
                if (bytes[12] == (byte) 169
                        && bytes[13] == (byte) 254
                        && bytes[14] == (byte) 169
                        && bytes[15] == (byte) 254) {
                    return true;
                }
                if (bytes[12] == (byte) 169
                        && bytes[13] == (byte) 254
                        && bytes[14] == (byte) 170
                        && bytes[15] == (byte) 2) {
                    return true;
                }
            }
        }

        return false;
    }
}
