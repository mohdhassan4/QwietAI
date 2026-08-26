package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility to validate URLs against Server-Side Request Forgery (SSRF) attacks. Ensures the URL
 * scheme is http/https and the resolved host is not a private, loopback, link-local, or metadata
 * address.
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates that the given URL string is safe from SSRF attacks.
     *
     * @param urlString the URL to validate
     * @return true if the URL has a safe scheme and resolves to a public (non-internal) host
     */
    public static boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }
        try {
            URL url = new URL(urlString);
            String scheme = url.getProtocol();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return false;
            }
            String host = url.getHost();
            if (host == null || host.isBlank()) {
                return false;
            }
            // Strip IPv6 brackets if present
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            InetAddress address = InetAddress.getByName(host);
            return !isInternalAddress(address);
        } catch (MalformedURLException | UnknownHostException e) {
            return false;
        }
    }

    private static boolean isInternalAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCloudMetadataAddress(address);
    }

    private static boolean isCloudMetadataAddress(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            // 169.254.0.0/16 (link-local, includes cloud metadata 169.254.169.254)
            return (addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254;
        }
        if (addr.length == 16) {
            // IPv4-mapped IPv6: ::ffff:169.254.x.x
            boolean isV4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isV4Mapped = false;
                    break;
                }
            }
            if (isV4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                return (addr[12] & 0xFF) == 169 && (addr[13] & 0xFF) == 254;
            }
        }
        return false;
    }
}
