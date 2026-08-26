package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Validates URL hosts to prevent SSRF (Server-Side Request Forgery) attacks by rejecting URLs that
 * resolve to private, reserved, or link-local IP address ranges.
 */
public final class UrlHostValidator {

    private UrlHostValidator() {}

    /**
     * Returns true if the URL host is safe to connect to (not a private/reserved/link-local
     * address and not using the file protocol).
     *
     * @param url the URL string to validate
     * @return true if the host is safe, false otherwise
     */
    public static boolean isHostSafe(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol();
            if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
                return false;
            }
            String host = parsedUrl.getHost();
            if (host == null || host.isBlank()) {
                return false;
            }
            return !isPrivateOrReserved(host);
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /**
     * Returns true if the URL object's host is safe to connect to.
     *
     * @param parsedUrl the parsed URL to validate
     * @return true if the host is safe, false otherwise
     */
    public static boolean isHostSafe(URL parsedUrl) {
        if (parsedUrl == null) {
            return false;
        }
        String protocol = parsedUrl.getProtocol();
        if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
            return false;
        }
        String host = parsedUrl.getHost();
        if (host == null || host.isBlank()) {
            return false;
        }
        return !isPrivateOrReserved(host);
    }

    private static boolean isPrivateOrReserved(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            return address.isLoopbackAddress()
                    || address.isSiteLocalAddress()
                    || address.isLinkLocalAddress()
                    || address.isAnyLocalAddress()
                    || address.isMulticastAddress()
                    || isInCloudMetadataRange(address);
        } catch (UnknownHostException e) {
            // If the host cannot be resolved, block it to be safe
            return true;
        }
    }

    private static boolean isInCloudMetadataRange(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            // 169.254.0.0/16 (link-local, includes cloud metadata 169.254.169.254)
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            if (first == 169 && second == 254) {
                return true;
            }
        }
        return false;
    }
}
