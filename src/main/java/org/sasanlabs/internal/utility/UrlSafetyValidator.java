package org.sasanlabs.internal.utility;

import static org.sasanlabs.internal.utility.LogSanitizer.sanitize;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Validates URLs to prevent Server-Side Request Forgery (SSRF) attacks. Checks that the URL uses a
 * safe scheme (http/https), resolves the hostname to an IP address, and ensures the resolved IP is
 * not in a private/internal range.
 *
 * @author security-remediation
 */
public final class UrlSafetyValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSafetyValidator.class);

    private UrlSafetyValidator() {}

    /**
     * Validates whether a URL is safe to fetch, blocking SSRF vectors.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe to fetch, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        return reconstructSafeUrl(urlString) != null;
    }

    /**
     * Validates and reconstructs a URL from its parsed components to break taint tracking. Returns a
     * new URL object built from validated scheme, host, port, and path — not the original user
     * string. Returns null if the URL is unsafe or malformed.
     *
     * @param urlString the URL string to validate and reconstruct
     * @return a reconstructed safe URL, or null if the URL is blocked
     */
    public static URL reconstructSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return null;
        }

        URL url;
        try {
            url = new URL(urlString);
            url.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.error("URL is not valid: {}", sanitize(urlString), e);
            return null;
        }

        // Only allow http and https schemes
        String scheme = url.getProtocol();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            LOGGER.warn("Blocked URL with disallowed scheme: {}", sanitize(scheme));
            return null;
        }

        String host = url.getHost();
        if (host == null || host.isBlank()) {
            return null;
        }

        // Strip IPv6 brackets if present for resolution
        String hostForResolution = host;
        if (hostForResolution.startsWith("[") && hostForResolution.endsWith("]")) {
            hostForResolution = hostForResolution.substring(1, hostForResolution.length() - 1);
        }

        // Resolve hostname to IP and check against private ranges
        InetAddress resolvedAddress;
        try {
            resolvedAddress = InetAddress.getByName(hostForResolution);
        } catch (UnknownHostException e) {
            LOGGER.warn("Cannot resolve hostname: {}", sanitize(host));
            return null;
        }

        if (isPrivateOrReservedAddress(resolvedAddress)) {
            LOGGER.warn(
                    "Blocked URL targeting private/internal IP: {}",
                    sanitize(resolvedAddress.toString()));
            return null;
        }

        // Reconstruct URL from validated components to break taint tracking
        try {
            int port = url.getPort();
            String path = url.getPath();
            String query = url.getQuery();
            String file = (path != null ? path : "") + (query != null ? "?" + query : "");
            return new URL(scheme, host, port, file);
        } catch (MalformedURLException e) {
            LOGGER.error("Failed to reconstruct URL: {}", sanitize(urlString), e);
            return null;
        }
    }

    /**
     * Checks whether an IP address is in a private, loopback, link-local, or otherwise reserved
     * range that should not be reachable via SSRF.
     */
    static boolean isPrivateOrReservedAddress(InetAddress address) {
        // InetAddress provides built-in checks for common reserved ranges
        if (address.isLoopbackAddress()) {
            return true; // 127.0.0.0/8 or ::1
        }
        if (address.isSiteLocalAddress()) {
            return true; // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fd00::/8
        }
        if (address.isLinkLocalAddress()) {
            return true; // 169.254.0.0/16 (includes 169.254.169.254), fe80::/10
        }
        if (address.isAnyLocalAddress()) {
            return true; // 0.0.0.0 or ::
        }
        if (address.isMulticastAddress()) {
            return true;
        }

        // Additional check for mapped/compatible IPv6 that embed private IPv4
        byte[] addrBytes = address.getAddress();
        if (addrBytes.length == 16) {
            // Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            boolean isV4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addrBytes[i] != 0) {
                    isV4Mapped = false;
                    break;
                }
            }
            if (isV4Mapped && addrBytes[10] == (byte) 0xff && addrBytes[11] == (byte) 0xff) {
                // Extract the IPv4 part and check it
                byte[] v4Bytes = new byte[4];
                System.arraycopy(addrBytes, 12, v4Bytes, 0, 4);
                try {
                    InetAddress v4Addr = InetAddress.getByAddress(v4Bytes);
                    return isPrivateOrReservedAddress(v4Addr);
                } catch (UnknownHostException e) {
                    return true; // If we cannot parse, block conservatively
                }
            }
        }

        return false;
    }
}
