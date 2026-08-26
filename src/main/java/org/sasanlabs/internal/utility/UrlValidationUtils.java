package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class for validating URLs against SSRF attacks. Rejects non-HTTP(S) schemes and
 * destinations targeting private/internal IP ranges or reserved hostnames.
 */
public final class UrlValidationUtils {

    private UrlValidationUtils() {}

    /**
     * Validates that the given URL is safe to request: uses HTTP or HTTPS scheme and does not
     * target a private, loopback, or link-local IP address or reserved hostname.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe to fetch; false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            url.toURI(); // syntax check

            // Only allow http and https schemes
            String protocol = url.getProtocol().toLowerCase();
            if (!protocol.equals("http") && !protocol.equals("https")) {
                return false;
            }

            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }

            // Check for blocked hostnames
            if (isBlockedHostname(host)) {
                return false;
            }

            // Strip IPv6 brackets if present for address parsing
            String addressStr = host;
            if (addressStr.startsWith("[") && addressStr.endsWith("]")) {
                addressStr = addressStr.substring(1, addressStr.length() - 1);
            }

            // Check if host is an IP address (IPv4 or IPv6) and validate
            if (isIpAddress(addressStr)) {
                InetAddress address = InetAddress.getByName(addressStr);
                if (isPrivateOrReserved(address)) {
                    return false;
                }
            }

            return true;
        } catch (MalformedURLException | URISyntaxException | UnknownHostException e) {
            return false;
        }
    }

    /**
     * Determines whether the given string is an IP address literal (IPv4 or IPv6) as opposed to a
     * hostname.
     */
    private static boolean isIpAddress(String host) {
        // IPv6 addresses contain colons
        if (host.contains(":")) {
            return true;
        }
        // IPv4 addresses: all characters are digits or dots, and contain at least one dot
        if (host.contains(".") && host.chars().allMatch(c -> Character.isDigit(c) || c == '.')) {
            return true;
        }
        return false;
    }

    /** Checks whether the hostname is a known internal/reserved name. */
    private static boolean isBlockedHostname(String host) {
        String lower = host.toLowerCase();
        return lower.equals("localhost")
                || lower.equals("localhost.localdomain")
                || lower.endsWith(".local")
                || lower.endsWith(".internal")
                || lower.equals("metadata.google.internal")
                || lower.equals("[::1]")
                || lower.equals("0.0.0.0");
    }

    /**
     * Checks whether the given address belongs to a private, loopback, or link-local range that
     * should not be reachable via user-supplied URLs.
     */
    private static boolean isPrivateOrReserved(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || isCarrierGradeNat(address);
    }

    /** Checks for 100.64.0.0/10 (Carrier-Grade NAT / Shared Address Space). */
    private static boolean isCarrierGradeNat(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            // 100.64.0.0/10 means first octet = 100, second octet in [64..127]
            return first == 100 && second >= 64 && second <= 127;
        }
        return false;
    }
}
