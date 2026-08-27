package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class providing URL validation to prevent SSRF (Server-Side Request Forgery) attacks. URLs
 * are validated to ensure they only reference public, non-internal hosts.
 */
public final class UrlValidationUtils {

    private UrlValidationUtils() {}

    /**
     * Validates that a URL is safe for server-side fetching. Rejects URLs targeting private,
     * loopback, link-local, or metadata IP addresses.
     *
     * @param urlString the URL string to validate
     * @return true if the URL targets a public host and uses http/https protocol
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
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (!isPublicAddress(address)) {
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            return false;
        }

        return true;
    }

    private static boolean isPublicAddress(InetAddress address) {
        if (address.isLoopbackAddress()) {
            return false;
        }
        if (address.isSiteLocalAddress()) {
            return false;
        }
        if (address.isLinkLocalAddress()) {
            return false;
        }
        if (address.isAnyLocalAddress()) {
            return false;
        }
        if (address.isMulticastAddress()) {
            return false;
        }

        byte[] addr = address.getAddress();
        // Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
        if (addr.length == 16) {
            boolean isIPv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isIPv4Mapped = false;
                    break;
                }
            }
            if (isIPv4Mapped && addr[10] == (byte) 0xff && addr[11] == (byte) 0xff) {
                // Extract the IPv4 portion and check it
                byte[] ipv4 = new byte[4];
                System.arraycopy(addr, 12, ipv4, 0, 4);
                try {
                    InetAddress ipv4Addr = InetAddress.getByAddress(ipv4);
                    return isPublicAddress(ipv4Addr);
                } catch (UnknownHostException e) {
                    return false;
                }
            }
        }

        return true;
    }
}
