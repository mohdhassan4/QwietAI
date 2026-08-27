package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class to validate URLs against SSRF attacks. Rejects URLs that resolve to
 * private/internal IP ranges or use non-HTTP(S) schemes.
 */
public final class UrlSsrfValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSsrfValidator.class);

    private UrlSsrfValidator() {}

    /**
     * Validates that the given URL is safe from SSRF attacks.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe (public, HTTP/HTTPS), false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
            url.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.debug("URL validation failed - malformed URL: {}", urlString, e);
            return false;
        }

        // Only allow http and https schemes
        String protocol = url.getProtocol().toLowerCase();
        if (!"http".equals(protocol) && !"https".equals(protocol)) {
            LOGGER.debug("URL validation failed - disallowed scheme: {}", protocol);
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Resolve hostname to IP and check for private/internal ranges
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReservedAddress(address)) {
                    LOGGER.debug(
                            "URL validation failed - private/internal IP detected: {}",
                            address.getHostAddress());
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            LOGGER.debug("URL validation failed - cannot resolve host: {}", host, e);
            return false;
        }

        return true;
    }

    /**
     * Checks whether the given InetAddress is a private, loopback, link-local, or otherwise
     * reserved address that should not be accessed via SSRF-prone endpoints.
     */
    private static boolean isPrivateOrReservedAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCloudMetadataAddress(address);
    }

    /**
     * Checks for cloud metadata service IPs (169.254.169.254, fd00:ec2::254, etc.).
     * InetAddress.isLinkLocalAddress() covers 169.254.0.0/16 and fe80::/10, but we also
     * explicitly check common cloud metadata endpoints.
     */
    private static boolean isCloudMetadataAddress(InetAddress address) {
        byte[] addr = address.getAddress();

        // IPv4: 169.254.169.254 (AWS/GCP/Azure metadata) - already covered by isLinkLocalAddress
        // but be explicit for clarity
        if (addr.length == 4) {
            if ((addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254) {
                return true;
            }
        }

        // IPv6: fd00::/8 (unique local addresses)
        if (addr.length == 16) {
            if ((addr[0] & 0xFF) == 0xFD) {
                return true;
            }
        }

        return false;
    }
}
