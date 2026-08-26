package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Validates URLs to prevent Server-Side Request Forgery (SSRF) attacks. Rejects internal/private IP
 * ranges, link-local addresses, loopback, and non-HTTP protocols.
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates that the given URL is safe from SSRF attacks.
     *
     * @param urlString the URL to validate
     * @return true if the URL is safe (public host, http/https only), false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            return false;
        }

        String protocol = url.getProtocol();
        if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isBlank()) {
            return false;
        }

        // Remove IPv6 brackets if present
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        try {
            InetAddress address = InetAddress.getByName(host);
            return !isPrivateOrReserved(address);
        } catch (UnknownHostException e) {
            // Cannot resolve host - reject to be safe
            return false;
        }
    }

    private static boolean isPrivateOrReserved(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCloudMetadataAddress(address);
    }

    private static boolean isCloudMetadataAddress(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            // 169.254.169.254 (AWS/GCP/Azure metadata)
            // 169.254.170.2 (AWS ECS metadata)
            if ((addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254) {
                return true;
            }
        }
        if (addr.length == 16) {
            // Check for IPv4-mapped IPv6 forms of metadata addresses
            // ::ffff:169.254.x.x
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                if ((addr[12] & 0xFF) == 169 && (addr[13] & 0xFF) == 254) {
                    return true;
                }
            }
        }
        return false;
    }
}
