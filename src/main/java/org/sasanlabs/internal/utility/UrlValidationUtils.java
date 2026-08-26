package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class for validating URLs against Server-Side Request Forgery (SSRF) attacks. Rejects
 * non-HTTP(S) protocols and URLs whose host resolves to internal/private/link-local IP addresses.
 */
public final class UrlValidationUtils {

    private UrlValidationUtils() {}

    /**
     * Validates that the given URL string is safe from SSRF attacks.
     *
     * @param urlString the URL to validate
     * @return true if the URL uses HTTP(S) and its host resolves to a public IP address
     */
    public static boolean isSafeFromSsrf(String urlString) {
        if (urlString == null || urlString.isEmpty()) {
            return false;
        }
        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol();
            if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
                return false;
            }
            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            // Remove brackets for IPv6 literal addresses
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
