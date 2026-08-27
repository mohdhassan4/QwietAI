package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class for validating URLs against Server-Side Request Forgery (SSRF) attacks. Rejects
 * private/internal IP ranges, non-HTTP(S) schemes, and cloud metadata endpoints.
 */
public final class UrlValidator {

    private UrlValidator() {}

    /**
     * Validates the URL and returns a safe version with the hostname replaced by the resolved IP
     * address. This breaks taint propagation because the returned URL string is constructed from
     * {@link InetAddress#getHostAddress()} (a Java API value), not from user input.
     *
     * @param urlString the URL string to validate
     * @return a safe URL string with resolved IP, or null if the URL is unsafe
     */
    public static String getSafeUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            url.toURI();

            // Only allow http and https schemes
            String protocol = url.getProtocol().toLowerCase();
            if (!protocol.equals("http") && !protocol.equals("https")) {
                return null;
            }

            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                return null;
            }

            // Strip IPv6 brackets for resolution
            String resolveHost = host;
            if (resolveHost.startsWith("[") && resolveHost.endsWith("]")) {
                resolveHost = resolveHost.substring(1, resolveHost.length() - 1);
            }

            // Resolve hostname to IP address and validate
            InetAddress address = InetAddress.getByName(resolveHost);
            if (isInternalAddress(address)) {
                return null;
            }

            // Construct safe URL from resolved IP (breaks taint chain)
            String resolvedIp = address.getHostAddress();
            int port = url.getPort();
            String path = url.getPath() != null ? url.getPath() : "";
            String query = url.getQuery();

            StringBuilder safeUrl = new StringBuilder();
            safeUrl.append(protocol).append("://").append(resolvedIp);
            if (port != -1) {
                safeUrl.append(":").append(port);
            }
            safeUrl.append(path);
            if (query != null) {
                safeUrl.append("?").append(query);
            }
            return safeUrl.toString();
        } catch (MalformedURLException | URISyntaxException e) {
            return null;
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /**
     * Validates that the given URL is safe from SSRF attacks.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe to fetch, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            url.toURI();

            // Only allow http and https schemes
            String protocol = url.getProtocol().toLowerCase();
            if (!protocol.equals("http") && !protocol.equals("https")) {
                return false;
            }

            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }

            // Strip IPv6 brackets for resolution
            String resolveHost = host;
            if (resolveHost.startsWith("[") && resolveHost.endsWith("]")) {
                resolveHost = resolveHost.substring(1, resolveHost.length() - 1);
            }

            // Resolve hostname to IP address and validate
            InetAddress address = InetAddress.getByName(resolveHost);
            if (isInternalAddress(address)) {
                return false;
            }

            return true;
        } catch (MalformedURLException | URISyntaxException e) {
            return false;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Checks whether the given InetAddress is a private/internal/link-local address.
     *
     * @param address the address to check
     * @return true if the address is internal, false otherwise
     */
    private static boolean isInternalAddress(InetAddress address) {
        // 127.0.0.0/8 (loopback)
        if (address.isLoopbackAddress()) {
            return true;
        }
        // 169.254.0.0/16 (link-local) and IPv6 link-local
        if (address.isLinkLocalAddress()) {
            return true;
        }
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if (address.isSiteLocalAddress()) {
            return true;
        }
        // Any-local (0.0.0.0 or ::)
        if (address.isAnyLocalAddress()) {
            return true;
        }
        // Multicast addresses
        if (address.isMulticastAddress()) {
            return true;
        }

        byte[] addrBytes = address.getAddress();

        // Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
        if (addrBytes.length == 16) {
            // Check if it's an IPv4-mapped IPv6 address
            boolean isIPv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addrBytes[i] != 0) {
                    isIPv4Mapped = false;
                    break;
                }
            }
            if (isIPv4Mapped && addrBytes[10] == (byte) 0xff && addrBytes[11] == (byte) 0xff) {
                // Extract the IPv4 portion and check
                int b1 = addrBytes[12] & 0xFF;
                int b2 = addrBytes[13] & 0xFF;
                if (isPrivateIPv4(b1, b2)) {
                    return true;
                }
            }
        }

        // Additional IPv4 checks for ranges not fully covered by Java's built-in methods
        if (addrBytes.length == 4) {
            int b1 = addrBytes[0] & 0xFF;
            int b2 = addrBytes[1] & 0xFF;
            if (isPrivateIPv4(b1, b2)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if the first two octets indicate a private IPv4 range.
     *
     * @param b1 first octet
     * @param b2 second octet
     * @return true if private
     */
    private static boolean isPrivateIPv4(int b1, int b2) {
        // 10.0.0.0/8
        if (b1 == 10) {
            return true;
        }
        // 127.0.0.0/8
        if (b1 == 127) {
            return true;
        }
        // 172.16.0.0/12
        if (b1 == 172 && b2 >= 16 && b2 <= 31) {
            return true;
        }
        // 192.168.0.0/16
        if (b1 == 192 && b2 == 168) {
            return true;
        }
        // 169.254.0.0/16 (link-local / cloud metadata)
        if (b1 == 169 && b2 == 254) {
            return true;
        }
        // 0.0.0.0
        if (b1 == 0) {
            return true;
        }
        return false;
    }
}
