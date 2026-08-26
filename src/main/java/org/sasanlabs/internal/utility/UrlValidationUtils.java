package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

/**
 * Utility class for validating URLs against Server-Side Request Forgery (SSRF) attacks. Rejects
 * non-HTTP(S) protocols and URLs whose host resolves to internal/private/link-local IP addresses.
 */
public final class UrlValidationUtils {

    private UrlValidationUtils() {}

    /**
     * Validates that the given URL string is safe from SSRF attacks and returns a canonical URI
     * constructed from validated components. Returns {@code null} if the URL is invalid or unsafe.
     *
     * @param urlString the URL to validate
     * @return a validated canonical URI, or null if the URL is invalid or targets an internal host
     */
    public static URI getValidatedUri(String urlString) {
        if (urlString == null || urlString.isEmpty()) {
            return null;
        }
        try {
            URI uri = new URI(urlString);
            String scheme = uri.getScheme();
            if (scheme == null
                    || (!"http".equalsIgnoreCase(scheme)
                            && !"https".equalsIgnoreCase(scheme))) {
                return null;
            }
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return null;
            }
            InetAddress address = InetAddress.getByName(host);
            if (isInternalAddress(address)) {
                return null;
            }
            // Reconstruct a canonical URI from validated components to break the taint chain
            return new URI(
                    scheme.toLowerCase(),
                    uri.getUserInfo(),
                    host,
                    uri.getPort(),
                    uri.getPath(),
                    uri.getQuery(),
                    uri.getFragment());
        } catch (URISyntaxException | UnknownHostException e) {
            return null;
        }
    }

    /**
     * Validates that the given URL string is safe from SSRF attacks.
     *
     * @param urlString the URL to validate
     * @return true if the URL uses HTTP(S) and its host resolves to a public IP address
     */
    public static boolean isSafeFromSsrf(String urlString) {
        return getValidatedUri(urlString) != null;
    }

    private static boolean isInternalAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCarrierGradeNat(address);
    }

    /**
     * Checks for 100.64.0.0/10 (Shared Address Space / Carrier-grade NAT).
     */
    private static boolean isCarrierGradeNat(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            return first == 100 && second >= 64 && second <= 127;
        }
        return false;
    }
}
