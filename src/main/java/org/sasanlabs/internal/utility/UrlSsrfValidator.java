package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Set;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Rejects
 * non-HTTP(S) schemes and URLs resolving to private/internal/link-local IP addresses.
 */
public final class UrlSsrfValidator {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    private UrlSsrfValidator() {}

    /**
     * Validates that the given URL string is safe from SSRF attacks.
     *
     * @param urlString the URL to validate
     * @return true if the URL uses an allowed scheme and does not resolve to a private/internal
     *     address; false otherwise
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

        String scheme = url.getProtocol();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Strip brackets from IPv6 addresses
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReserved(address)) {
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            return false;
        }

        return true;
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
            // 169.254.0.0/16 (link-local, includes cloud metadata 169.254.169.254)
            return (addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254;
        }
        if (addr.length == 16) {
            // Check for IPv4-mapped IPv6 addresses (::ffff:A.B.C.D)
            boolean isV4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isV4Mapped = false;
                    break;
                }
            }
            if (isV4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                // Extract the IPv4 portion
                return (addr[12] & 0xFF) == 169 && (addr[13] & 0xFF) == 254
                        || (addr[12] & 0xFF) == 10
                        || ((addr[12] & 0xFF) == 172
                                && (addr[13] & 0xFF) >= 16
                                && (addr[13] & 0xFF) <= 31)
                        || ((addr[12] & 0xFF) == 192 && (addr[13] & 0xFF) == 168)
                        || ((addr[12] & 0xFF) == 127);
            }
        }
        return false;
    }
}
